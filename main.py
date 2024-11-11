import os
import hashlib
import numpy as np
import re
from joblib import load
from scipy.stats import entropy
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import queue

# Paths to the virus database and model
virus_database_file_path = 'VirusDataBaseHash.bav' 
model_path = 'virus_detection_model.joblib'
STOP_SIGNAL = "__STOP__"

# Load virus database from file
def load_virus_database(file_path):
    virus_hashes = []
    try:
        with open(file_path, 'r') as file:
            for line in file:
                if ':' in line:
                    parts = line.strip().split(':', 1)
                    if len(parts) == 2:
                        hash_value = parts[0]
                        if re.fullmatch(r'[a-fA-F0-9]{64}', hash_value):
                            virus_hashes.append(hash_value)
    except Exception as e:
        print(f"Error loading virus database: {e}")
    return virus_hashes

# Feature extraction function
def extract_features(file_path, chunk_size=4096):
    features = {}
    try:
        file_size = os.path.getsize(file_path)
        if file_size > 100 * 1024 * 1024:
            return None  # Skip large files
        features['file_size'] = file_size
        with open(file_path, 'rb') as file:
            data = file.read(chunk_size)
            features['entropy'] = entropy(list(data), base=2) if data else 0
        features['extension'] = 1 if file_path.endswith(('.exe', '.dll', '.bin')) else 0
        features['hash_mod'] = int(hashlib.sha256(data).hexdigest(), 16) % (10 ** 8)
    except Exception as e:
        print(f"Error extracting features from {file_path}: {e}")
        return None
    return [features['file_size'], features['entropy'], features['extension'], features['hash_mod']]

# Main app class with threading and file handling optimizations
class VirusScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Virus Scanner")
        self.geometry("700x500")

        self.virus_database = load_virus_database(virus_database_file_path)
        self.model = load(model_path)
        self.scanning = False
        self.file_queue = queue.Queue()
        self.results_queue = queue.Queue()

        # Setting up tabs
        self.tab_control = ttk.Notebook(self)
        self.virus_tab = ttk.Frame(self.tab_control)
        self.potential_virus_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.virus_tab, text="Virus")
        self.tab_control.add(self.potential_virus_tab, text="Potentially Virus")
        self.tab_control.pack(expand=1, fill="both")

        # Listboxes to display results
        self.virus_listbox = tk.Listbox(self.virus_tab, selectmode=tk.SINGLE)
        self.virus_listbox.pack(fill="both", expand=True)
        self.potential_virus_listbox = tk.Listbox(self.potential_virus_tab)
        self.potential_virus_listbox.pack(fill="both", expand=True)

        # Frame for Start and Stop buttons at the bottom
        button_frame = tk.Frame(self)
        button_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=10)

        self.start_button = tk.Button(button_frame, text="Start Scanning", command=self.start_scanning)
        self.start_button.pack(side=tk.LEFT, padx=10)

        self.stop_button = tk.Button(button_frame, text="Stop Scanning", command=self.stop_scanning, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=10)

        # Popup menu for delete functionality
        self.popup_menu = tk.Menu(self, tearoff=0)
        self.popup_menu.add_command(label="Delete", command=self.delete_selected_file)
        
        # Bind right-click to show popup menu
        self.virus_listbox.bind("<Button-3>", self.show_popup_menu)

    def show_popup_menu(self, event):
        try:
            self.virus_listbox.selection_clear(0, tk.END)
            self.virus_listbox.selection_set(self.virus_listbox.nearest(event.y))
            self.popup_menu.post(event.x_root, event.y_root)
        finally:
            self.popup_menu.grab_release()

    def delete_selected_file(self):
        selected_index = self.virus_listbox.curselection()
        if selected_index:
            file_path = self.virus_listbox.get(selected_index)
            try:
                os.remove(file_path)
                self.virus_listbox.delete(selected_index)
                messagebox.showinfo("Success", f"{file_path} has been deleted.")
            except Exception as e:
                messagebox.showerror("Error", f"Could not delete {file_path}: {e}")

    def start_scanning(self):
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.scanning = True

        # Start directory scanning in a separate thread
        scan_thread = threading.Thread(target=self.scan_directory, args=('/Users/apple/Downloads',))
        scan_thread.start()

        # Start the worker thread for processing files from the queue
        worker_thread = threading.Thread(target=self.process_files_from_queue)
        worker_thread.daemon = True
        worker_thread.start()

        # Periodically check for completed tasks to update the GUI
        self.check_results_queue()

    def stop_scanning(self):
        self.scanning = False
        self.file_queue.put(STOP_SIGNAL)  # Signal the worker thread to stop
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def add_to_listbox(self, file_path, list_type):
        if list_type == "Virus":
            self.virus_listbox.insert(tk.END, file_path)
        else:
            self.potential_virus_listbox.insert(tk.END, file_path)

    def scan_directory(self, directory_path):
        for root, _, files in os.walk(directory_path):
            if not self.scanning:
                break
            for file_name in files:
                file_path = os.path.join(root, file_name)
                self.file_queue.put(file_path)  # Add file to queue for processing
        self.file_queue.put(STOP_SIGNAL)  # Signal end of scanning

    def process_files_from_queue(self):
        while self.scanning:
            try:
                file_path = self.file_queue.get(timeout=1)
                if file_path == STOP_SIGNAL:
                    break

                with open(file_path, 'rb') as file:
                    data = file.read(4096)
                    file_hash = hashlib.sha256(data).hexdigest()

                if file_hash in self.virus_database:
                    self.results_queue.put((file_path, "Virus"))
                else:
                    file_features = extract_features(file_path)
                    if file_features is None:
                        continue
                    
                    file_features = np.array(file_features).reshape(1, -1)
                    prediction_proba = self.model.predict_proba(file_features)[0][1]
                    
                    if prediction_proba >= 0.9:
                        self.results_queue.put((file_path, "Potentially Virus"))
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Could not scan file {file_path}: {e}")
            finally:
                self.file_queue.task_done()

    def check_results_queue(self):
        # Batch update to GUI to reduce lag
        try:
            batch_size = 10  # Adjust batch size as needed
            for _ in range(batch_size):
                file_path, list_type = self.results_queue.get_nowait()
                self.add_to_listbox(file_path, list_type)
                self.results_queue.task_done()
        except queue.Empty:
            pass

        if self.scanning:
            self.after(100, self.check_results_queue)  # Check again after 100ms if still scanning

# Run the application
app = VirusScannerApp()
app.mainloop()
