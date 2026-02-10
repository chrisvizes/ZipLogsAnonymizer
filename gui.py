#!/usr/bin/env python3
"""
ZipLogsAnonymizer GUI - Interactive treemap visualization for log anonymization.

Uses pywebview with D3.js treemap to show real-time processing progress.
"""

import sys
import multiprocessing
import os

# CRITICAL: This must be called BEFORE any other code on Windows frozen executables.
multiprocessing.freeze_support()


def _is_worker_process():
    """Check if current process is a multiprocessing worker."""
    return multiprocessing.current_process().name != "MainProcess"


# Only import GUI modules in the main process
if not _is_worker_process():
    import threading
    import json
    from pathlib import Path

    import webview

    # Lazy-loaded anonymizer module (deferred to avoid blocking GUI startup)
    _anonymizer_module = None
    _anonymizer_lock = threading.Lock()

    def _get_anonymizer():
        """Lazy-load the anonymizer module on first use."""
        global _anonymizer_module
        if _anonymizer_module is not None:
            return _anonymizer_module
        with _anonymizer_lock:
            if _anonymizer_module is not None:
                return _anonymizer_module
            if not getattr(sys, 'frozen', False):
                from rust_build_helper import ensure_rust_core
                ensure_rust_core()
            import anonymizer
            _anonymizer_module = anonymizer
            return anonymizer

    def get_assets_path():
        """Get the path to GUI assets, handling both dev and frozen modes."""
        if getattr(sys, 'frozen', False):
            # Running as frozen executable
            base_path = Path(sys._MEIPASS)
        else:
            # Running as script
            base_path = Path(__file__).parent

        return base_path / 'gui_assets'

    class Api:
        """
        Python API exposed to JavaScript.
        Handles file operations and processing control.
        """

        def __init__(self):
            self.window = None
            self.processing = False
            self.cancel_requested = False
            self.output_dir = None
            self.current_file = None
            self._processing_thread = None

        def set_window(self, window):
            """Set the webview window reference."""
            self.window = window

        def browse_file(self):
            """Open file dialog to select a zip file."""
            file_types = ('Zip files (*.zip)', 'All files (*.*)')
            result = self.window.create_file_dialog(
                webview.OPEN_DIALOG,
                allow_multiple=False,
                file_types=file_types
            )

            if result and len(result) > 0:
                file_path = result[0]
                self._on_file_selected(file_path)

        def _on_file_selected(self, file_path: str):
            """Handle file selection."""
            zip_path = Path(file_path)

            # Update UI immediately
            self.window.evaluate_js(f'setFilePath({json.dumps(str(file_path))})')
            self.window.evaluate_js('setButtonState("process-btn", false)')
            self.window.evaluate_js('setButtonState("open-folder-btn", false)')
            self.window.evaluate_js(f'setStatus("Analyzing: {zip_path.name}...")')
            self.window.evaluate_js('resetStats()')

            # Store path
            self.current_file = file_path
            self.output_dir = zip_path.parent / (zip_path.stem + "_anonymized")

            # Analyze zip file in background thread
            threading.Thread(
                target=self._analyze_and_init_treemap,
                args=(file_path,),
                daemon=True,
            ).start()

        def _analyze_and_init_treemap(self, zip_path: str):
            """Analyze zip file and send manifest to treemap (runs on background thread)."""
            import zipfile

            try:
                anon = _get_anonymizer()

                with zipfile.ZipFile(zip_path, 'r') as zf:
                    entries = [e for e in zf.infolist() if not e.is_dir()]

                    # Categorize files
                    large_files = []
                    small_files_count = 0
                    small_files_size = 0
                    binary_files_count = 0
                    binary_files_size = 0

                    for entry in entries:
                        ext = Path(entry.filename).suffix.lower()
                        size_mb = entry.file_size / (1024 * 1024)

                        if ext in anon.TEXT_EXTENSIONS:
                            if entry.file_size >= anon.LARGE_FILE_THRESHOLD:
                                large_files.append({
                                    'name': entry.filename,
                                    'size_mb': round(size_mb, 2)
                                })
                            else:
                                small_files_count += 1
                                small_files_size += size_mb
                        else:
                            binary_files_count += 1
                            binary_files_size += size_mb

                    # Build manifest
                    manifest = {
                        'largeFiles': large_files,
                        'smallFiles': {
                            'count': small_files_count,
                            'total_mb': round(small_files_size, 2)
                        },
                        'binaryFiles': {
                            'count': binary_files_count,
                            'total_mb': round(binary_files_size, 2)
                        }
                    }

                    # Send to JavaScript
                    self.window.evaluate_js(f'initTreemap({json.dumps(manifest)})')

                zip_name = Path(zip_path).name
                self.window.evaluate_js(f'setStatus("Selected: {zip_name}")')
                self.window.evaluate_js('setButtonState("process-btn", true)')

            except zipfile.BadZipFile:
                self.window.evaluate_js('setStatus("Error: File is not a valid zip archive.")')
            except Exception as e:
                error_msg = str(e).replace('"', '\\\\"')
                self.window.evaluate_js(f'setStatus("Error reading zip: {error_msg}")')

        def start_processing(self):
            """Start the anonymization process."""
            if self.processing:
                return

            self.processing = True
            self.cancel_requested = False

            # Update UI state
            self.window.evaluate_js('setButtonState("process-btn", false)')
            self.window.evaluate_js('setButtonState("browse-btn", false)')
            self.window.evaluate_js('setButtonState("cancel-btn", true)')
            self.window.evaluate_js('setButtonState("open-folder-btn", false)')
            self.window.evaluate_js('setStatus("Processing...")')
            self.window.evaluate_js('resetStats()')
            self.window.evaluate_js('processingStarted()')

            # Get options from UI
            options = self.window.evaluate_js('getOptions()')

            # Start processing thread
            self._processing_thread = threading.Thread(
                target=self._run_processing,
                args=(self.current_file, options),
                daemon=True
            )
            self._processing_thread.start()

        def _run_processing(self, zip_path: str, options: dict):
            """Run the processing in background thread."""
            try:
                create_zip = options.get('createZip', True)
                keep_uncompressed = options.get('keepUncompressed', True)

                anon = _get_anonymizer()
                success = anon.process_zip(
                    zip_path,
                    cancel_check=self._check_cancel,
                    progress_callback=self._progress_callback,
                    create_zip=create_zip,
                    keep_uncompressed=keep_uncompressed
                )

                # Determine output paths
                zip_file = Path(zip_path)
                output_dir_path = str(self.output_dir) if self.output_dir and self.output_dir.exists() else None
                output_zip_path = None
                if create_zip:
                    potential_zip = zip_file.parent / (zip_file.stem + "_anonymized.zip")
                    if potential_zip.exists():
                        output_zip_path = str(potential_zip)

                # Schedule UI update on main thread
                was_cancelled = self.cancel_requested
                self.window.evaluate_js(
                    f'processingComplete({json.dumps(success and not was_cancelled)}, {json.dumps(output_dir_path)}, {json.dumps(output_zip_path)})'
                )

                # Update final state
                self._on_processing_complete(success, was_cancelled)

            except Exception as e:
                print(f"Processing error: {e}")
                self._on_processing_complete(False, False)

        def _check_cancel(self) -> bool:
            """Check if cancellation was requested."""
            return self.cancel_requested

        def _progress_callback(self, event: dict):
            """Handle progress events from anonymizer."""
            event_type = event.get('type')

            if event_type == 'file_status':
                name = event.get('name', '')
                status = event.get('status', 'queued')

                # Handle special group names
                if name == 'small_files':
                    self.window.evaluate_js(f'updateGroupStatus("small_files", "{status}")')
                elif name == 'binary_files':
                    self.window.evaluate_js(f'updateGroupStatus("binary_files", "{status}")')
                else:
                    self.window.evaluate_js(
                        f'updateFileStatus({json.dumps(name)}, "{status}")'
                    )

            elif event_type == 'stats':
                stats = {
                    'progress_pct': event.get('progress_pct'),
                    'throughput_mbs': event.get('throughput_mbs'),
                    'eta_seconds': event.get('eta_seconds'),
                    'total_mb': event.get('total_mb')
                }
                # Filter out None values
                stats = {k: v for k, v in stats.items() if v is not None}
                if stats:
                    self.window.evaluate_js(f'updateStats({json.dumps(stats)})')

            elif event_type == 'creating_zip':
                self.window.evaluate_js('showCreatingZip()')

        def _on_processing_complete(self, success: bool, was_cancelled: bool):
            """Handle processing completion."""
            self.processing = False
            self.cancel_requested = False

            # Update UI state
            self.window.evaluate_js('setButtonState("process-btn", true)')
            self.window.evaluate_js('setButtonState("browse-btn", true)')
            self.window.evaluate_js('setButtonState("cancel-btn", false)')

            if was_cancelled:
                self.window.evaluate_js('setStatus("Cancelled. No output created.")')
                self.output_dir = None
            elif success and self.output_dir and self.output_dir.exists():
                self.window.evaluate_js('setStatus("Complete! Output ready.")')
                self.window.evaluate_js('setButtonState("open-folder-btn", true)')
            else:
                self.window.evaluate_js('setStatus("Processing failed. Check console for details.")')
                self.output_dir = None

        def cancel_processing(self):
            """Request cancellation of processing."""
            if self.processing and not self.cancel_requested:
                self.cancel_requested = True
                self.window.evaluate_js('setButtonState("cancel-btn", false)')
                self.window.evaluate_js('setStatus("Cancelling... please wait")')

        def open_output_folder(self):
            """Open the output folder in file explorer."""
            if self.output_dir and self.output_dir.exists():
                if sys.platform == 'win32':
                    os.startfile(self.output_dir)
                elif sys.platform == 'darwin':
                    os.system(f'open "{self.output_dir}"')
                else:
                    os.system(f'xdg-open "{self.output_dir}"')

    def main():
        """Main entry point for the GUI application."""
        api = Api()

        # Get path to HTML file
        assets_path = get_assets_path()
        html_path = assets_path / 'index.html'

        # Check if assets exist
        if not html_path.exists():
            print(f"Error: GUI assets not found at {html_path}")
            print("Make sure gui_assets/ folder is present.")
            sys.exit(1)

        # Create webview window
        window = webview.create_window(
            title='ZipLogsAnonymizer',
            url=str(html_path),
            js_api=api,
            width=900,
            height=700,
            min_size=(700, 550),
            text_select=False
        )

        api.set_window(window)

        # Start the webview
        webview.start(debug=False)


if __name__ == "__main__":
    if not _is_worker_process():
        main()
