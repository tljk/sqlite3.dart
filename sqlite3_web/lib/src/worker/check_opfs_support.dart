import 'dart:js_interop';
import 'dart:js_interop_unsafe';

// ignore: implementation_imports
import 'package:sqlite3/src/wasm/js_interop/new_file_system_access.dart';
import 'package:web/web.dart'
    show
        FileSystemDirectoryHandle,
        FileSystemFileHandle,
        FileSystemSyncAccessHandle;

import '../locks.dart';

typedef OpfsSupport = ({bool basicSupport, bool supportsReadWriteUnsafe});

/// Checks whether the OPFS API is likely to be correctly implemented in the
/// current browser.
///
/// Since OPFS uses the synchronous file system access API, this method can only
/// return true when called in a dedicated worker.
Future<OpfsSupport> checkOpfsSupport() async {
  const noSupport = (basicSupport: false, supportsReadWriteUnsafe: false);
  final storage = storageManager;

  if (storage == null) return noSupport;

  const testFileName = '_drift_feature_detection';

  FileSystemDirectoryHandle? opfsRoot;
  FileSystemFileHandle? fileHandle;
  JSObject? openedFile;
  HeldLock? lock;
  var canOpenWithReadWriteUnsafe = false;

  try {
    // We can't use OPFS concurrently, this avoids races when multiple tabs try
    // to open a database at the same time.
    lock = await WebLocks.instance?.request(testFileName);
    opfsRoot = await storage.directory;

    fileHandle = await opfsRoot.openFile(testFileName, create: true);
    (canOpenWithReadWriteUnsafe, openedFile) =
        await _tryOpeningWithReadWriteUnsafe(fileHandle);

    // In earlier versions of the OPFS standard, some methods like `getSize()`
    // on a sync file handle have actually been asynchronous. We don't support
    // Browsers that implement the outdated spec.
    final getSizeResult = openedFile.callMethod('getSize'.toJS);
    if (getSizeResult.typeofEquals('object')) {
      // Returned a promise, that's no good.
      await (getSizeResult as JSPromise).toDart;
      return noSupport;
    }

    return (
      basicSupport: true,
      supportsReadWriteUnsafe: canOpenWithReadWriteUnsafe,
    );
  } on Object {
    return noSupport;
  } finally {
    lock?.release();
    if (openedFile != null) {
      (openedFile as FileSystemSyncAccessHandle).close();
    }

    if (opfsRoot != null && fileHandle != null) {
      await opfsRoot.remove(testFileName);
    }
  }
}

Future<(bool, FileSystemSyncAccessHandle)> _tryOpeningWithReadWriteUnsafe(
  FileSystemFileHandle handle,
) async {
  FileSystemSyncAccessHandle? opened;

  try {
    // First, try opening with readwrite-unsafe
    opened = await ProposedLockingSchemeApi(handle)
        .createSyncAccessHandle(
          FileSystemCreateSyncAccessHandleOptions.unsafeReadWrite(),
        )
        .toDart;

    // The mode is supported if we can do it again (that means no lock has been
    // applied).
    final openedAgain = await ProposedLockingSchemeApi(handle)
        .createSyncAccessHandle(
          FileSystemCreateSyncAccessHandleOptions.unsafeReadWrite(),
        )
        .toDart;
    openedAgain.close();

    return (true, opened);
  } catch (e) {
    opened?.close();

    // Fallback to opening without the special option.
    final sync = await handle.createSyncAccessHandle().toDart;
    return (false, sync);
  }
}
