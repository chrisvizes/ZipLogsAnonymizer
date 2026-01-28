#!/usr/bin/env python3
"""
ZipLogsAnonymizer GUI - Simple graphical interface for log anonymization.

This provides a user-friendly way to anonymize zip files without using the command line.
"""

import sys
import multiprocessing

# CRITICAL: This must be called BEFORE any other code on Windows frozen executables.
# It allows worker processes spawned by ProcessPoolExecutor to initialize correctly
# without re-running the main script.
multiprocessing.freeze_support()

# Check if this is a worker process in a frozen executable.
# Workers should not import GUI modules or run GUI code.
def _is_worker_process():
    """Check if current process is a multiprocessing worker."""
    return multiprocessing.current_process().name != 'MainProcess'

# Only import GUI modules in the main process
if not _is_worker_process():
    import threading
    import tkinter as tk
    from tkinter import ttk, filedialog, scrolledtext
    from pathlib import Path
    import queue
    import os

    # Import the core anonymization logic
    from anonymizer import process_zip, TEXT_EXTENSIONS


    class RedirectText:
        """Redirect stdout/stderr to a tkinter text widget."""

        def __init__(self, text_widget, message_queue):
            self.text_widget = text_widget
            self.message_queue = message_queue

        def write(self, string):
            self.message_queue.put(string)

        def flush(self):
            pass


    class AnonymizerGUI:
        """Main GUI application for ZipLogsAnonymizer."""

        def __init__(self, root):
            self.root = root
            self.root.title("ZipLogsAnonymizer")
            self.root.geometry("700x500")
            self.root.minsize(600, 400)

            # Message queue for thread-safe UI updates
            self.message_queue = queue.Queue()

            # Track processing state
            self.processing = False
            self.output_dir = None
            self.cancel_requested = False

            self._create_widgets()
            self._setup_output_redirect()
            self._process_queue()

        def _create_widgets(self):
            """Create all GUI widgets."""
            # Main container with padding
            main_frame = ttk.Frame(self.root, padding="10")
            main_frame.grid(row=0, column=0, sticky="nsew")

            # Configure grid weights for resizing
            self.root.columnconfigure(0, weight=1)
            self.root.rowconfigure(0, weight=1)
            main_frame.columnconfigure(0, weight=1)
            main_frame.rowconfigure(3, weight=1)  # Output area gets the space

            # Header
            header_frame = ttk.Frame(main_frame)
            header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))

            title_label = ttk.Label(
                header_frame,
                text="ZipLogsAnonymizer",
                font=("Segoe UI", 16, "bold")
            )
            title_label.pack(anchor="w")

            desc_label = ttk.Label(
                header_frame,
                text="Anonymize sensitive data in log archives for safe sharing",
                font=("Segoe UI", 9)
            )
            desc_label.pack(anchor="w")

            # File selection frame
            file_frame = ttk.LabelFrame(main_frame, text="Select Zip File", padding="10")
            file_frame.grid(row=1, column=0, sticky="ew", pady=(0, 10))
            file_frame.columnconfigure(0, weight=1)

            self.file_path_var = tk.StringVar()
            self.file_entry = ttk.Entry(file_frame, textvariable=self.file_path_var, state="readonly")
            self.file_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))

            self.browse_button = ttk.Button(file_frame, text="Browse...", command=self._browse_file)
            self.browse_button.grid(row=0, column=1)

            # Supported formats hint
            formats = ", ".join(sorted(TEXT_EXTENSIONS))
            hint_label = ttk.Label(
                file_frame,
                text=f"Text formats processed: {formats}",
                font=("Segoe UI", 8),
                foreground="gray"
            )
            hint_label.grid(row=1, column=0, columnspan=2, sticky="w", pady=(5, 0))

            # Stats display frame (throughput and ETA)
            stats_frame = ttk.LabelFrame(main_frame, text="Performance", padding="10")
            stats_frame.grid(row=2, column=0, sticky="ew", pady=(0, 10))
            stats_frame.columnconfigure(1, weight=1)

            # Throughput display
            ttk.Label(stats_frame, text="Throughput:", font=("Segoe UI", 9)).grid(row=0, column=0, sticky="w", padx=(0, 10))
            self.throughput_var = tk.StringVar(value="--")
            self.throughput_label = ttk.Label(
                stats_frame,
                textvariable=self.throughput_var,
                font=("Segoe UI", 14, "bold"),
                foreground="#0066cc"
            )
            self.throughput_label.grid(row=0, column=1, sticky="w")

            # ETA display
            ttk.Label(stats_frame, text="ETA:", font=("Segoe UI", 9)).grid(row=0, column=2, sticky="w", padx=(30, 10))
            self.eta_var = tk.StringVar(value="--")
            self.eta_label = ttk.Label(
                stats_frame,
                textvariable=self.eta_var,
                font=("Segoe UI", 14, "bold"),
                foreground="#009933"
            )
            self.eta_label.grid(row=0, column=3, sticky="w")

            # Progress percentage
            ttk.Label(stats_frame, text="Progress:", font=("Segoe UI", 9)).grid(row=0, column=4, sticky="w", padx=(30, 10))
            self.progress_var = tk.StringVar(value="--")
            self.progress_label = ttk.Label(
                stats_frame,
                textvariable=self.progress_var,
                font=("Segoe UI", 14, "bold"),
                foreground="#cc6600"
            )
            self.progress_label.grid(row=0, column=5, sticky="w")

            # Output area
            output_frame = ttk.LabelFrame(main_frame, text="Log Output", padding="10")
            output_frame.grid(row=3, column=0, sticky="nsew", pady=(0, 10))
            output_frame.columnconfigure(0, weight=1)
            output_frame.rowconfigure(0, weight=1)

            self.output_text = scrolledtext.ScrolledText(
                output_frame,
                wrap=tk.WORD,
                font=("Consolas", 9),
                height=12,
                state="disabled"
            )
            self.output_text.grid(row=0, column=0, sticky="nsew")

            # Button frame
            button_frame = ttk.Frame(main_frame)
            button_frame.grid(row=4, column=0, sticky="ew")

            self.process_button = ttk.Button(
                button_frame,
                text="Anonymize",
                command=self._start_processing,
                state="disabled"
            )
            self.process_button.pack(side="left")

            self.cancel_button = ttk.Button(
                button_frame,
                text="Cancel",
                command=self._cancel_processing,
                state="disabled"
            )
            self.cancel_button.pack(side="left", padx=(10, 0))

            self.open_folder_button = ttk.Button(
                button_frame,
                text="Open Output Folder",
                command=self._open_output_folder,
                state="disabled"
            )
            self.open_folder_button.pack(side="left", padx=(10, 0))

            # Status bar
            self.status_var = tk.StringVar(value="Select a zip file to begin")
            status_bar = ttk.Label(
                main_frame,
                textvariable=self.status_var,
                font=("Segoe UI", 9),
                foreground="gray"
            )
            status_bar.grid(row=5, column=0, sticky="w", pady=(5, 0))

        def _setup_output_redirect(self):
            """Redirect stdout to the output text widget."""
            self.redirector = RedirectText(self.output_text, self.message_queue)

        def _process_queue(self):
            """Process messages from the queue and update the text widget."""
            import re
            try:
                while True:
                    message = self.message_queue.get_nowait()
                    self.output_text.configure(state="normal")

                    # Handle carriage return for progress bar updates
                    if message.startswith('\r'):
                        # Delete the current line and insert new content
                        self.output_text.delete("end-1c linestart", "end-1c")
                        message = message[1:]  # Remove the \r

                    self.output_text.insert(tk.END, message)
                    self.output_text.see(tk.END)
                    self.output_text.configure(state="disabled")

                    # Parse throughput and ETA from large file progress output
                    # Format: "Avg: X.XX MB/s | ETA: Xm Xs"
                    avg_match = re.search(r'Avg:\s*([\d.]+)\s*MB/s', message)
                    if avg_match:
                        self.throughput_var.set(f"{float(avg_match.group(1)):.2f} MB/s")

                    eta_match = re.search(r'ETA:\s*(\d+[hms]\s*(?:\d+[ms]\s*)?(?:\d+s)?)', message)
                    if eta_match:
                        self.eta_var.set(eta_match.group(1).strip())

                    # Parse progress from small files progress bar
                    # Format: "[====----] 50% (100/200)"
                    progress_match = re.search(r'(\d+)%\s*\((\d+)/(\d+)\)', message)
                    if progress_match:
                        pct = progress_match.group(1)
                        current = progress_match.group(2)
                        total = progress_match.group(3)
                        self.progress_var.set(f"{pct}% ({current}/{total})")

                    # Parse large file progress
                    # Format: "[X/Y]" for completed files
                    large_progress_match = re.search(r'\[(\d+)/(\d+)\].*DONE', message)
                    if large_progress_match:
                        current = int(large_progress_match.group(1))
                        total = int(large_progress_match.group(2))
                        pct = int(current * 100 / total) if total > 0 else 0
                        self.progress_var.set(f"{pct}% ({current}/{total} files)")

            except queue.Empty:
                pass

            # Schedule next check
            self.root.after(50, self._process_queue)

        def _browse_file(self):
            """Open file dialog to select a zip file."""
            filename = filedialog.askopenfilename(
                title="Select Zip File",
                filetypes=[
                    ("Zip files", "*.zip"),
                    ("All files", "*.*")
                ]
            )

            if filename:
                self.file_path_var.set(filename)
                self.process_button.configure(state="normal")
                self.status_var.set(f"Selected: {Path(filename).name}")
                self.open_folder_button.configure(state="disabled")
                self.output_dir = None

                # Clear previous output
                self.output_text.configure(state="normal")
                self.output_text.delete(1.0, tk.END)
                self.output_text.configure(state="disabled")

        def _cancel_processing(self):
            """Request cancellation of the current processing."""
            if self.processing and not self.cancel_requested:
                self.cancel_requested = True
                self.cancel_button.configure(state="disabled")
                self.status_var.set("Cancelling... please wait")

        def _check_cancel(self) -> bool:
            """Check if cancellation has been requested. Called by anonymizer."""
            return self.cancel_requested

        def _start_processing(self):
            """Start the anonymization process in a background thread."""
            if self.processing:
                return

            zip_path = self.file_path_var.get()
            if not zip_path:
                return

            self.processing = True
            self.cancel_requested = False
            self.process_button.configure(state="disabled")
            self.browse_button.configure(state="disabled")
            self.cancel_button.configure(state="normal")
            self.open_folder_button.configure(state="disabled")
            self.status_var.set("Processing...")

            # Reset stats display
            self.throughput_var.set("--")
            self.eta_var.set("--")
            self.progress_var.set("--")

            # Calculate expected output directory
            zip_file = Path(zip_path)
            self.output_dir = zip_file.parent / (zip_file.stem + "_anonymized")

            # Clear output
            self.output_text.configure(state="normal")
            self.output_text.delete(1.0, tk.END)
            self.output_text.configure(state="disabled")

            # Start processing in background thread
            thread = threading.Thread(target=self._process_file, args=(zip_path,), daemon=True)
            thread.start()

        def _process_file(self, zip_path):
            """Process the file (runs in background thread)."""
            # Redirect stdout to our text widget
            old_stdout = sys.stdout
            old_stderr = sys.stderr
            sys.stdout = self.redirector
            sys.stderr = self.redirector

            try:
                success = process_zip(zip_path, cancel_check=self._check_cancel)

                # Schedule UI update on main thread
                was_cancelled = self.cancel_requested
                self.root.after(0, lambda: self._processing_complete(success, was_cancelled))

            except Exception as e:
                print(f"\nError: {e}")
                self.root.after(0, lambda: self._processing_complete(False, False))

            finally:
                sys.stdout = old_stdout
                sys.stderr = old_stderr

        def _processing_complete(self, success, was_cancelled=False):
            """Called when processing is complete."""
            self.processing = False
            self.cancel_requested = False
            self.process_button.configure(state="normal")
            self.browse_button.configure(state="normal")
            self.cancel_button.configure(state="disabled")

            if was_cancelled:
                self.status_var.set("Cancelled. No output created.")
                self.output_dir = None
            elif success and self.output_dir and self.output_dir.exists():
                self.status_var.set("Complete! Output ready.")
                self.open_folder_button.configure(state="normal")
            else:
                self.status_var.set("Processing failed. Check output for details.")
                self.output_dir = None

        def _open_output_folder(self):
            """Open the output folder in file explorer."""
            if self.output_dir and self.output_dir.exists():
                # Cross-platform folder open
                if sys.platform == "win32":
                    os.startfile(self.output_dir)
                elif sys.platform == "darwin":
                    os.system(f'open "{self.output_dir}"')
                else:
                    os.system(f'xdg-open "{self.output_dir}"')


    def main():
        """Main entry point for the GUI application."""
        root = tk.Tk()

        # Set app icon if available
        try:
            # On Windows, you could set an icon here
            pass
        except Exception:
            pass

        app = AnonymizerGUI(root)
        root.mainloop()


if __name__ == "__main__":
    # Only run main() if this is the main process
    if not _is_worker_process():
        main()
