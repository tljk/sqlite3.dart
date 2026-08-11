import 'dart:convert';
import 'dart:io';

import 'package:uuid/uuid.dart';
import 'package:pubspec_parse/pubspec_parse.dart';

import 'download_sqlite.dart' as download_sqlite;

/// Generates a CycloneDX SBOM for precompiled artifacts we attach to GitHub
/// releases.
///
/// These SBOMs don't contain Dart dependencies (as those are trivial for users
/// to infer through the pub dependency graph), only binaries.
///
/// Currently, we only generate SBOMs for the `sqlite3_connection_pool` package
/// and for a plain `sqlite3` build (no SQLCipher or SQLite3 Multiple Ciphers).
void main(List<String> args) async {
  final sbom = switch (args) {
    ['sqlite3_connection_pool'] => await _generateForSqlite3ConnectionPool(),
    ['sqlite3'] => await _generateForSqlite3(),
    _ => throw ArgumentError(
        'Usage: dart tool/generate_sbom.dart <sqlite3_connection_pool>')
  };

  print(JsonEncoder.withIndent(' ' * 2).convert(sbom));
}

Future<Object?> _generateForSqlite3() async {
  final pubspec = await _parsePubspec('sqlite3');
  var versionNumber =
      int.parse(download_sqlite.sqlitePath.split('-')[2]) ~/ 100;
  final sqlite3Patch = versionNumber % 100;
  versionNumber ~/= 100;
  final sqlite3Minor = versionNumber % 100;
  versionNumber ~/= 100;
  final sqlite3Major = versionNumber;

  return {
    ..._commonFields(),
    'metadata': {
      'timestamp': DateTime.now().toIso8601String(),
      'lifecycles': [
        {'phase': 'pre-build'}
      ],
      'authors': _authors,
      'component': {
        'type': 'library',
        'authors': _authors,
        'name': 'sqlite3',
        'version': pubspec.version.toString(),
        'licenses': [
          {'expression': 'MIT'}
        ],
        'bom-ref': 'pkg-sqlite3',
        'purl': 'pkg:pub/sqlite3',
        'externalReferences': [
          {'type': 'vcs', 'url': 'https://github.com/simolus3/sqlite3.git'},
          {
            'type': 'documentation',
            'url': 'https://pub.dev/documentation/sqlite3/'
          },
        ]
      }
    },
    'components': [
      {
        'version': '$sqlite3Major.$sqlite3Minor.$sqlite3Patch',
        'bom-ref': 'sqlite3',
        'license': [
          {'expression': 'blessing'}
        ],
        'externalReferences': [
          {'url': 'https://sqlite.org/', 'type': 'website'},
        ],
        'cpe':
            'cpe:2.3:a:sqlite:sqlite:$sqlite3Major.$sqlite3Minor.$sqlite3Patch:*:*:*:*:*:*:*',
      },
    ],
    'dependencies': [
      {
        'ref': 'pkg-sqlite3',
        'dependsOn': ['sqlite3', 'openssl'],
      }
    ],
  };
}

Future<Object?> _generateForSqlite3ConnectionPool() async {
  // Currently, all Rust dependencies end up in the library (we have no build or
  // proc-macro dependencies).
  final processOutput = await Process.run(
    'cargo',
    ['metadata', '--format-version=1'],
    workingDirectory: 'sqlite3_connection_pool',
  );
  if (processOutput.exitCode != 0) {
    throw 'Could not run cargo metadata: ${processOutput.stderr}';
  }

  final metadata = jsonDecode(processOutput.stdout);
  final packages = (metadata['packages'] as List).cast<Map<String, Object?>>();

  final components = <Object?>[];
  final dependencies = <String>[];
  final pubspec = await _parsePubspec('sqlite3_connection_pool');

  for (final package in packages) {
    final name = package['name'] as String;
    if (name == 'sqlite3_connection_pool') {
      // We'll generate the component for this manually.
      continue;
    }

    final version = package['version'] as String;
    final license = package['license'] as String;
    final description = package['description'] as String;
    final bomRef = 'cargo@$name@$version';
    dependencies.add(bomRef);

    components.add({
      'name': name,
      'purl': 'pkg:cargo/$name@$version',
      'type': 'library',
      'version': version,
      'licenses': [
        {'expression': license}
      ],
      'bom-ref': bomRef,
      'description': description,
      'externalReferences': [
        if (package['repository'] case final String repository)
          {'type': 'vcs', 'url': repository},
        if (package['homepage'] case final String homepage)
          {'type': 'website', 'url': homepage},
        if (package['documentation'] case final String documentation)
          {'type': 'documentation', 'url': documentation},
      ],
      if (package['authors'] case [final String author]) 'author': author,
    });
  }

  return {
    ..._commonFields(),
    'metadata': {
      'timestamp': DateTime.now().toIso8601String(),
      'lifecycles': [
        {'phase': 'build'}
      ],
      'authors': _authors,
      'component': {
        'type': 'library',
        'authors': _authors,
        'name': 'sqlite3_connection_pool',
        'version': pubspec.version.toString(),
        'licenses': [
          {'expression': 'MIT'}
        ],
        'purl': 'pkg:pub/sqlite3_connection_pool',
        'externalReferences': [
          {'type': 'vcs', 'url': 'https://github.com/simolus3/sqlite3.git'},
          {
            'type': 'documentation',
            'url': 'https://pub.dev/documentation/sqlite3_connection_pool/'
          },
        ]
      },
    },
    'components': components,
    'dependencies': [
      {
        'ref': 'main',
        'dependsOn': dependencies,
      }
    ],
  };
}

Future<Pubspec> _parsePubspec(String package) async {
  final file = File('$package/pubspec.yaml');
  return Pubspec.parse(await file.readAsString(), sourceUrl: file.uri);
}

const _authors = [
  {'name': 'Simon Binder', 'email': 'oss@simonbinder.eu'}
];

Map<String, Object?> _commonFields() {
  return {
    'bomFormat': 'CycloneDX',
    'specVersion': '1.7',
    'serialNumber': 'urn:uuid:${const Uuid().v4()}',
    'version': 1,
  };
}
