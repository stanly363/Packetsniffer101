import tkinter as tk
from tkinter import ttk, messagebox
import pyshark
from pyshark.tshark.tshark import get_tshark_interfaces
import threading
import os
import sys
import asyncio

class PacketCaptureThread(threading.Thread):
    def __init__(self, interface, output_file, stop_event):
        super().__init__()
        self.interface = interface
        self.output_file = output_file
        self.stop_event = stop_event
        self.capture = None
        self.loop = None

    def run(self):
        # Initialize a new event loop for this thread
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

        try:
            self.capture = pyshark.LiveCapture(interface=self.interface, output_file=self.output_file)
            # Start sniffing without timeout
            self.capture.sniff(timeout=None)
        except Exception as e:
            # Communicate exception
            messagebox.showerror("Capture Error", f"An error occurred during packet capture:\n{e}")
        finally:
            if self.capture:
                self.capture.close()
            self.loop.close()

class PacketCaptureApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Capture Tool")
        self.capture_thread = None
        self.stop_event = threading.Event()


        self.interface_label = ttk.Label(root, text="Select Network Interface:")
        self.interface_label.pack(pady=10)

        self.interface_var = tk.StringVar()
        self.interface_combobox = ttk.Combobox(root, textvariable=self.interface_var, state="readonly", width=100)
        self.interface_combobox.pack(pady=5)


        self.populate_interfaces()

        # Create and place the Start and Stop buttons
        self.button_frame = ttk.Frame(root)
        self.button_frame.pack(pady=20)

        self.start_button = ttk.Button(self.button_frame, text="Start Capture", command=self.start_capture)
        self.start_button.grid(row=0, column=0, padx=10)

        self.stop_button = ttk.Button(self.button_frame, text="Stop Capture", command=self.stop_capture, state="disabled")
        self.stop_button.grid(row=0, column=1, padx=10)

        # Status label
        self.status_var = tk.StringVar()
        self.status_var.set("Status: Idle")
        self.status_label = ttk.Label(root, textvariable=self.status_var)
        self.status_label.pack(pady=10)

    def populate_interfaces(self):
        try:
            interfaces = get_tshark_interfaces()
            if not interfaces:
                messagebox.showerror("Error", "No network interfaces found.")
                self.root.destroy()
                return


            self.interface_combobox['values'] = interfaces
            self.interface_combobox.current(0)  # Select the first interface by default
        except Exception as e:
            messagebox.showerror("Error", f"Failed to retrieve interfaces:\n{e}")
            self.root.destroy()

    def start_capture(self):
        selected_interface = self.interface_var.get()
        if not selected_interface:
            messagebox.showwarning("Warning", "Please select a network interface.")
            return

        # Disable Start button and enable Stop button
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.status_var.set(f"Status: Capturing on {selected_interface}...")


        output_path = os.path.join(os.getcwd(), 'packet.pcap')


        self.stop_event.clear()


        self.capture_thread = PacketCaptureThread(interface=selected_interface, output_file=output_path, stop_event=self.stop_event)
        self.capture_thread.start()

    def stop_capture(self):
        if self.capture_thread and self.capture_thread.is_alive():
            self.status_var.set("Status: Stopping capture...")
            # Signal the capture thread to stop
            self.stop_event.set()
            try:

                asyncio.run_coroutine_threadsafe(self.close_capture(), self.capture_thread.loop)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to stop capture:\n{e}")
                self.start_button.config(state="normal")
                self.stop_button.config(state="disabled")
                self.status_var.set("Status: Idle")
                return


            self.capture_thread.join()

            self.start_button.config(state="normal")
            self.stop_button.config(state="disabled")
            self.status_var.set("Status: Capture stopped.")
            messagebox.showinfo("Info", "Packet capture has been stopped and saved to packet.pcap.")

    async def close_capture(self):
        if self.capture_thread and self.capture_thread.capture:
            await self.capture_thread.capture.close_async()

def main():
    try:
        root = tk.Tk()
        app = PacketCaptureApp(root)
        root.mainloop()
    except Exception as e:
        messagebox.showerror("Fatal Error", f"An unexpected error occurred:\n{e}")
        sys.exit(1)

if __name__ == "__main__":
    main()