import hashlib
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

def calculate_hash_text():
    """Calculate hash for the text based on the selected algorithm"""
    text = text_entry.get()
    algorithm = algorithm_var.get()
    if not text:
        messagebox.showwarning("Warning", "Please enter text!")
        return
    try:
        if algorithm == "MD5":
            hash_result = hashlib.md5(text.encode()).hexdigest()
        elif algorithm == "SHA-256":
            hash_result = hashlib.sha256(text.encode()).hexdigest()
        else:
            messagebox.showerror("Error", "Algorithm not supported!")
            return
        result_text_tab.delete("1.0", tk.END)  # Clear previous results
        result_text_tab.insert(tk.END, f"{algorithm} for text:\n{hash_result}")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

def calculate_hash_file():
    """Calculate hash for the file based on the selected algorithm"""
    file_path = filedialog.askopenfilename(title="Select File")
    algorithm = algorithm_var.get()
    if not file_path:
        return
    try:
        if algorithm == "MD5":
            hash_obj = hashlib.md5()
        elif algorithm == "SHA-256":
            hash_obj = hashlib.sha256()
        else:
            messagebox.showerror("Error", "Algorithm not supported!")
            return

        with open(file_path, "rb") as file:
            for chunk in iter(lambda: file.read(4096), b""):
                hash_obj.update(chunk)
        hash_result = hash_obj.hexdigest()
        result_file_tab.delete("1.0", tk.END)  # Clear previous results
        result_file_tab.insert(tk.END, f"File path: {file_path}\n\n{algorithm} for file:\n{hash_result}")
    except FileNotFoundError:
        messagebox.showerror("Error", "File not found!")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

# Setup the interface
root = tk.Tk()
root.title("MD5 and SHA-256 Hash Calculator")
root.geometry("600x500")
root.resizable(False, False)  # Disable window resizing

# Create a Notebook (Tabs)
notebook = ttk.Notebook(root)
notebook.pack(fill="both", expand=True, padx=10, pady=10)

# Select algorithm
algorithm_var = tk.StringVar(value="MD5")
algorithm_frame = ttk.Frame(root)
algorithm_frame.pack(fill="x", padx=20, pady=5)
ttk.Label(algorithm_frame, text="Select Algorithm:").pack(side="left", padx=5)
ttk.Radiobutton(algorithm_frame, text="MD5", variable=algorithm_var, value="MD5").pack(side="left", padx=5)
ttk.Radiobutton(algorithm_frame, text="SHA-256", variable=algorithm_var, value="SHA-256").pack(side="left", padx=5)

# Text Tab
text_tab = ttk.Frame(notebook)
notebook.add(text_tab, text="Hash Calculator for Text")

text_label = ttk.Label(text_tab, text="Enter text:")
text_label.pack(pady=10)

text_entry = ttk.Entry(text_tab, width=50, font=("Arial", 12))
text_entry.pack(pady=5)

text_button = ttk.Button(text_tab, text="Calculate", command=calculate_hash_text)
text_button.pack(pady=10)

result_text_tab = tk.Text(text_tab, height=10, font=("Arial", 12), wrap="word", relief="flat", padx=10, pady=10)
result_text_tab.pack(pady=10, fill="both", expand=True)

# File Tab
file_tab = ttk.Frame(notebook)
notebook.add(file_tab, text="Hash Calculator for File")

file_label = ttk.Label(file_tab, text="Select file to calculate hash:")
file_label.pack(pady=20)

file_button = ttk.Button(file_tab, text="Choose File", command=calculate_hash_file)
file_button.pack(pady=5)

result_file_tab = tk.Text(file_tab, height=10, font=("Arial", 12), wrap="word", relief="flat", padx=10, pady=10)
result_file_tab.pack(pady=10, fill="both", expand=True)

# Run the application
root.mainloop()