"""ASCII welcome screen for Cyberpm."""
import tkinter as tk
from tkinter import ttk
from startup_art import ascii_art


class WelcomeScreen(ttk.Frame):
    def __init__(self,parent,on_audit,on_workspace):
        super().__init__(parent)
        self.art=ascii_art()
        self.canvas=tk.Canvas(self,bg='#0b1019',highlightthickness=0)
        self.canvas.pack(fill='both',expand=True)
        self.title=self.canvas.create_text(0,0,text='CYBERPM',fill='#e6edf3',font=('Consolas',22,'bold'))
        self.drawing=self.canvas.create_text(0,0,text=self.art,fill='#3f777c',font=('Consolas',9),justify='left')
        self.caption=self.canvas.create_text(0,0,text='Auditoria web • Evidências • Validação',fill='#8b949e',font=('Segoe UI',11))
        controls=ttk.Frame(self,padding=10); controls.pack(fill='x')
        ttk.Button(controls,text='Iniciar auditoria',command=on_audit,style='Start.TButton').pack(side='left',padx=8)
        ttk.Button(controls,text='Central de auditoria',command=on_workspace,style='Accent.TButton').pack(side='left')
        self.canvas.bind('<Configure>',self.resize)

    def resize(self,event):
        lines=self.art.splitlines(); columns=max(map(len,lines),default=1)
        size=max(4,min(13,int(min((event.width-30)/(columns*0.85),(event.height-110)/(len(lines)*1.8)))))
        self.canvas.itemconfigure(self.drawing,font=('Consolas',size))
        self.canvas.coords(self.title,event.width/2,30)
        self.canvas.coords(self.drawing,event.width/2,(event.height+10)/2)
        self.canvas.coords(self.caption,event.width/2,event.height-22)
