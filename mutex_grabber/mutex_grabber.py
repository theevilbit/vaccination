"""
Create mutexes on a PC so malware won't install itself

"""

import re
import time
import sys

import json
import requests
from bs4 import BeautifulSoup

from ctypes import *
from ctypes.wintypes import *

import Tkinter as tk
from tkinter import BOTH, YES
from tkFileDialog import askopenfilename
from tkFileDialog import asksaveasfilename

import traceback

from functools import partial
from multiprocessing import Queue
import multiprocessing


def add_to_fifo(l,element):
	"""
	Remove last element if queue = 50, and insert one
	"""
	if len(l) == 50:
		l.pop(0)
	l.append(element)
	return l

def check_mutex(q):
	"""
	Function to track malwr.com for new analysis pages, and if there is a new, open it and extract mutexes
	"""
	visited = []
	user_agent = {'User-agent': 'Mozilla/5.0'}
	known_malware_sig = 'File has been identified by at least one AntiVirus on VirusTotal as malicious'
	print '[*] Mutex grabber started...'
	while True:
		try:
			result = requests.get('https://malwr.com/analysis/', headers=user_agent)
			print '[+] Refreshed main page'
			matches = re.findall(r'analysis/[a-zA-Z0-9]*/',result.content)
			if matches:
				for match in matches:
					try:
						if match not in visited:
							visited = add_to_fifo(visited,match)
							analysis_result = requests.get('https://malwr.com/' + match, headers=user_agent)
							print '[+] Downloaded analysis: ' + 'https://malwr.com/' + match
							parsed_analysis_result = BeautifulSoup(analysis_result.content, "html.parser")
							summary_mutexes = parsed_analysis_result.find(id="summary_mutexes")
							summary_mutexes = str(summary_mutexes).split()
							for entry in summary_mutexes:
								if 'br' in entry:
									mutex = entry.replace('<br/>','').strip()
									q.put(mutex)
					except Exception,ex:
						template = "An exception of type {0} occurred. Arguments:\n{1!r}"
						message = template.format(type(ex).__name__, ex.args)
						print message
						traceback.print_exc(file=sys.stdout)
		except Exception,ex:
			template = "An exception of type {0} occurred. Arguments:\n{1!r}"
			message = template.format(type(ex).__name__, ex.args)
			print message
			traceback.print_exc(file=sys.stdout)
		time.sleep(60)

class MutexTracker(tk.Frame):
	def __init__(self, *args, **kwargs):
		tk.Frame.__init__(self, root, background="#ffffff")
		self.canvas = tk.Canvas(root, borderwidth=0, background="#ffffff")
		self.frame = tk.Frame(self.canvas, background="#ffffff")
		self.canvas.pack(fill=BOTH, expand=YES)
		self.frame.pack(fill=BOTH, expand=YES)
		self.vsb = tk.Scrollbar(root, orient="vertical", command=self.canvas.yview)
		self.canvas.configure(yscrollcommand=self.vsb.set)

		self.vsb.pack(side="right", fill="y")
		self.canvas.pack(side="left", fill="both", expand=True)
		self.canvas.create_window((4,4), window=self.frame, anchor="nw", tags="self.frame")

		self.frame.bind("<Configure>", self.on_frameconfigure)
		self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)
		root.protocol("WM_DELETE_WINDOW", self.on_exit)
		
		self.grid_columnconfigure(1, weight=1)

		tk.Button(self, text='Load mutexes from file', command=self.open_mutex_file).grid(row=0, column=0, sticky="ew")
		tk.Button(self, text='Save mutexes to file', command=self.save_mutex_file).grid(row=1, column=0, sticky="ew")
		tk.Button(self, text='Load whitelist from file', command=self.open_whitelist_file).grid(row=2, column=0, sticky="ew")
		tk.Button(self, text='Save whitelist to file', command=self.save_whitelist_file).grid(row=3, column=0, sticky="ew")
		tk.Button(self, text='Show whitelist', command=self.show_whitelist).grid(row=4, column=0, sticky="ew")
		
		tk.Label(self.frame, text="Name", anchor="w").grid(row=0, column=0, sticky="ew")
		tk.Label(self.frame, text="Active", anchor="w").grid(row=0, column=1, sticky="ew")
		tk.Label(self.frame, text="Whitelisted", anchor="w").grid(row=0, column=2, sticky="ew")
		
		self.row = 1
		self.q = Queue()
		self.new_process = multiprocessing.Process(
			target=check_mutex,
			args=(self.q,))
		self.new_process.start()
		self.after(100, self.listen_for_result)

		self.mutexes = {}
		self.whitelist = []		
		self.temp_mutex_file = 'temp_mutex.txt'
		self.temp_whitelist_file = 'temp_whitelist.txt'
		self.clear_temp_files()

	def on_exit(self):
		"""
		When you click to exit, this function is called
		"""
		self.save_mutexes(self.temp_mutex_file)
		self.save_mutex_whitelist(self.temp_whitelist_file)
		self.new_process.terminate()
		root.destroy()

	def on_frameconfigure(self, event):
		'''
		Reset the scroll region to encompass the inner frame
		'''
		self.canvas.configure(scrollregion=self.canvas.bbox("all"))
		
	def _on_mousewheel(self, event):
		'''
		Scroll window on mousewheel event
		'''
		self.canvas.yview_scroll(-1*(event.delta/120), "units") #Windows
		#self.canvas.yview_scroll(-1*(event.delta), "units") #osx
		
	def show_whitelist(self):
		toplevel = tk.Toplevel()
		toplevel.iconbitmap(r'lock.ico')
		toplevel.title('Mutex grabber')
		toplevel.configure(background='white')
		label = tk.Label(toplevel, text='\n'.join(self.whitelist), height=0, width=100)
		label.pack()
	
	def add_mutex(self, mutex):
		if mutex in self.mutexes:
			pass
		else:
			row = self.row
			name_label = tk.Label(self.frame, text=mutex, anchor="w")
			wl_state = tk.IntVar()
			mutex_state = tk.IntVar()
			mutex_state_cb = tk.Checkbutton(self.frame, variable=mutex_state, onvalue=True, offvalue=False)
			whitelist_state_cb = tk.Checkbutton(self.frame, variable=wl_state, onvalue=True, offvalue=False)
			action_state = partial(self.mutex_state_change, mutex, mutex_state_cb, whitelist_state_cb, mutex_state, wl_state)
			action_whitelist = partial(self.whitelist_state_change, mutex, mutex_state_cb, whitelist_state_cb, mutex_state, wl_state)
			mutex_state_cb.configure(command=action_state)
			whitelist_state_cb.configure(command=action_whitelist)
			name_label.grid(row=row, column=0, sticky="ew")
			mutex_state_cb.grid(row=row, column=1, sticky="ew")
			whitelist_state_cb.grid(row=row, column=2, sticky="ew")
			self.row += 1
			if mutex in self.whitelist:
				self.mutexes[mutex] = None
				whitelist_state_cb.select()
			else:
				hMutex = windll.kernel32.CreateMutexA(None,True,mutex)
				if hMutex:
					self.mutexes[mutex] = hMutex
					mutex_state_cb.select()
					print '[+] Created mutex: ' + mutex
				else:
					self.mutexes[mutex] = None
					print '[-] Couldn\'t create mutex: ' + mutex

	def whitelist_state_change(self, mutex, mutex_state_cb, whitelist_state_cb, mutex_state, wl_state):
		if wl_state.get() == 1:
			self.whitelist.append(mutex)
			if mutex_state.get() == 1:
				success = windll.kernel32.CloseHandle(self.mutexes[mutex])
				if success:
					self.mutexes[mutex] = None
					mutex_state_cb.deselect()
		elif wl_state.get() == 0:
			self.whitelist.remove(mutex)

	def mutex_state_change(self, mutex, mutex_state_cb, whitelist_state_cb, mutex_state, wl_state):
		'''
		Enable/disbale a given mutex (update checkbox and create/disable it)
		'''
		if wl_state.get() == 1:
			mutex_state_cb.deselect()
		elif wl_state.get() == 0:
			if mutex_state.get() == 0:
				success = windll.kernel32.CloseHandle(self.mutexes[mutex])
				if success:
					self.mutexes[mutex] = None
					mutex_state_cb.deselect()			
			if mutex_state.get() == 1:
				hMutex = windll.kernel32.CreateMutexA(None,True,mutex)
				if hMutex:
					self.mutexes[mutex] = hMutex
				else:
					mutex_state_cb.deselect()


	def clear_temp_files(self):
		f = open(self.temp_mutex_file,'w')
		f.close()
		f = open(self.temp_whitelist_file,'w')
		f.close()
		
	def open_mutex_file(self):
		"""
		Button handler - opening file with mutexes
		"""
		filename = askopenfilename()
		if filename:
			self.load_mutexes(filename)

	def save_mutex_file(self):
		"""
		Button handler - Saving mutexes to file
		"""
		filename = asksaveasfilename()
		if filename:
			self.save_mutexes(filename)

	def open_whitelist_file(self):
		"""
		Button handler - opening file with whitelisted mutexes
		"""
		filename = askopenfilename()
		if filename:
			self.load_mutex_whitelist(filename)

	def save_whitelist_file(self):
		"""
		Button handler - Saving whitelist to a file
		"""
		filename = asksaveasfilename()
		if filename:
			self.save_mutex_whitelist(filename)

	def load_mutexes(self, filename):
		'''
		load mutexes from file
		'''
		with open(filename,'r') as f:
			for line in f:
				self.add_mutex(line.strip())
	
	def save_mutexes(self, filename):
		'''
		Save current mutexes to a file
		'''
		with open(filename,'w') as f:
			for mutex in self.mutexes:
				f.write(mutex + '\n')
	
	def load_mutex_whitelist(self, filename):
		'''
		load mutex whitelist from file
		'''
		with open(filename,'r') as f:
			for line in f:
				mutex = line.strip()
				if mutex in self.whitelist:
					pass
				else:
					self.whitelist.append(mutex)

	def save_mutex_whitelist(self, filename):
		'''
		Save current whitelist to a file
		'''
		with open(filename,'w') as f:
			for item in self.whitelist:
				f.write(item + '\n')

	def listen_for_result(self):
		'''
		Check if there is something in the queue
		'''
		try:
			mutex = self.q.get(0)
			self.add_mutex(mutex)
			self.after(100, self.listen_for_result)
		except Exception,ex:
			if type(ex).__name__ == 'Empty':
				self.after(100, self.listen_for_result)
				pass
			else:
				template = "An exception of type {0} occurred. Arguments:\n{1!r}"
				message = template.format(type(ex).__name__, ex.args)
				print message
				traceback.print_exc(file=sys.stdout)
				self.after(100, self.listen_for_result)

if __name__ == "__main__":
	root = tk.Tk()
	MutexTracker(root, text="Mutex list").pack(side="top", fill="both", expand=True, padx=10, pady=10)
	root.iconbitmap(r'lock.ico')
	root.title('Mutex grabber')
	root.configure(background='white')
	root.mainloop()
