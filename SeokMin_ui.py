import SeokMin as rs
import sys
from PyQt5.QtWidgets import *
from PyQt5 import uic
import json

form_class = uic.loadUiType('./SeokMin.ui')[0]

class Mywindow(QMainWindow,form_class):
    def __init__(self,rs):
        super().__init__()
        self.setupUi(self)

        self.count = 0
        self.all_indicies = rs.all_indicies

        self.starttime =[]
        self.endtime = []
        self.Whole_PS_With_Hash_Table = []
        self.Check_Hash_return_data = {}
        self.WhiteList = []
        self.BlackList = []
        self.booting_first_time = []

        self.all_indices_view.itemClicked.connect(self.indices_list_click) #? 확인
        self.STB.itemClicked.connect(self.click_whitelist_tab_start_time_list) #? 확인
        self.ETB.itemClicked.connect(self.click_whitelist_tab_end_time_list) #? 확인
        self.EWB.clicked.connect(self.onButtonClicked)
        self.insertFile.clicked.connect(self.pushButtonClicked)
    
    def pushButtonClicked(self):
        print('[log]pushbtnclicked fname')
        fname = QFileDialog.getOpenFileName(self)
        self.Prompt_of_fileopen.setText(fname[0])
        self.WhiteList = rs.openWhitelist.to_make_whitelist(fname[0])
        for f in range(0,len(self.WhiteList)):
            self.whitelistbox.addItem(self.WhiteList[f][0])


    def click_btn1(self):
        print('[log] clear')
        del self.starttime
        del self.endtime
        del self.Whole_PS_With_Hash_Table
        del self.Check_Hash_return_data
        del self.WhiteList
        del self.BlackList
        del self.booting_first_time

        self.starttime = []
        self.endtime = []
        self.Whole_PS_With_Hash_Table = []
        self.Check_Hash_return_data = {}
        self.WhiteList = []
        self.BlackList = []
        self.booting_first_time = []

        self.DNS.clear()
        self.IP.clear()
        self.hostname.clear()
        self.Accesstime.clear()
        self.MRP.clear()
        self.MCP.clear()
        self.LHL.clear()
        self.CEE.clear()
        self.viroustotal_API.clear()
        self.viroustotal_API_Result.clear()
        self.SuspectTable.clear()
        self.Prompt_of_fileopen.clear()
        self.whitelistbox.clear()
        self.connected_host_list.clear()
        self.BCB.clear()
        self.STB.clear()
        self.ETB.clear()
        self.PW.clear()


    def inqury(self):
        print('[log] indices search ')
        self.all_indices_view.clear()
        for f in self.all_indicies:
            self.all_indices_view.addItem(f)
        count = self.count
        self.count = self.count +1
    
    def indices_list_click(self):
        print("[log] Clicked"+"__"+self.all_indices_view.currentItem().text())

        self.hostname.setText(rs.find_host_name(self.all_indices_view.currentItem().text()))
        
        self.Accesstime.setText(rs.find_access_time(self.all_indices_view.currentItem().text()))
        self.connected_host_list.addItem(rs.find_host_name(self.all_indices_view.currentItem().text()))
        self.DNS.addItem("================================================================")
        DNS = rs.find_dns(self.all_indices_view.currentItem().text())
        for f in range(0,len(DNS)):
            self.DNS.addItem(DNS[f])
        self.DNS.addItem("================================================================")
        
        self.IP.addItem("==========================================")
        IP = rs.find_IP(self.all_indices_view.currentItem().text())
        for f in range(0,len(IP)):
            self.IP.addItem(IP[f])
        self.IP.addItem("==========================================")

        self.MRP.addItem("====================================================================================================================================================================================")
        M_R_P = rs.find_most_running_process(self.all_indices_view.currentItem().text())
        for f in range(0,len(M_R_P)):
            self.MRP.addItem(M_R_P[f])
        self.MRP.addItem("====================================================================================================================================================================================")
 
        self.MCP.addItem("====================================================================================================================================================================================")
        M_C_P = rs.find_most_closing_process(self.all_indices_view.currentItem().text())
        for f in range(0,len(M_C_P)):
            self.MCP.addItem(M_C_P[f])
        self.MCP.addItem("====================================================================================================================================================================================")

        self.LHL.addItem("====================================================================================================================================================================================")
        L_H_L = rs.find_last_100_logs(self.all_indices_view.currentItem().text())
        for f in range(0,len(L_H_L)):
            self.LHL.addItem("["+str(f+1)+"]")
            self.LHL.addItem(L_H_L[f])
        self.LHL.addItem("====================================================================================================================================================================================")
        self.LHL.addItem("\n")

        C_E_E = rs.find_count_of_each_event_id(self.all_indices_view.currentItem().text())
        self.CEE.addItem("Total number of Event:   "+C_E_E[0])
        for f in range(1,len(C_E_E)):
            self.CEE.addItem("\t\t"+C_E_E[f])

        B_C_B = rs.find_booting_start_time(self.all_indices_view.currentItem().text())
        first_booting_time = rs.find_access_time(self.all_indices_view.currentItem().text())
        self.booting_first_time = first_booting_time[first_booting_time.find("[")+1:first_booting_time.find("]")]
        if len(B_C_B) == 0 or B_C_B[0] != self.booting_first_time:
            B_C_B.insert(0,self.booting_first_time)
        self.BCB.addItem("Booting count: %d" %int(len(B_C_B)))
        for f in range(len(B_C_B)):
            self.BCB.addItem("\t  "+str(f+1)+". \t"+B_C_B[f])
            self.STB.addItem(str(f+1)+".    "+B_C_B[f])

        E_T_B = rs.find_booting_end_time(self.all_indices_view.currentItem().text())
        for f in range(len(E_T_B)):
            self.ETB.addItem(str(f+1)+".    "+E_T_B[f])

    def click_whitelist_tab_start_time_list(self):
        starttime = self.STB.currentItem().text()
        s_count,starttime = map(str,starttime.split(".    "))
        self.starttime = starttime

    def click_whitelist_tab_end_time_list(self):
        endtime = self.ETB.currentItem().text()
        e_count,endtime = map(str,endtime.split(".    "))
        self.endtime = endtime
        whitelist = rs.find_whitelist_based_on_time(self.all_indices_view.currentItem().text(),self.starttime,endtime)
        for f in range(len(whitelist)):
                if whitelist[f][1].find("=") == 0:
                    filename = whitelist[f][0]
                    hash = whitelist[f][1]
                else:
                    filename = whitelist[f][1]
                    hash = whitelist[f][0]
                self.WhiteList.append("Filename="+filename+"/Hash"+hash)
                self.PW.addItem("Filename="+filename+"/Hash"+hash)

    def SearchBlackList(self):
        self.viroustotal_API_Result.clear()
        self.viroustotal_API.clear()
        self.SuspectTable.clear()
        print("[log] Clicked"+"__SearchBlackList")
        self.Whole_PS_With_Hash_Table =  rs.find_PS_With_Hash_table_list(self.all_indices_view.currentItem().text())
        if self.WhiteList is not None:
            for f in range(0,len(self.Whole_PS_With_Hash_Table)):
                continue_count = 0
                for s in range(0,len(self.WhiteList)):
                    if self.WhiteList[s][1]==self.Whole_PS_With_Hash_Table[f][0]:
                        if self.WhiteList[s][0] == self.Whole_PS_With_Hash_Table[f][1]:
                            continue_count = 1
                if continue_count is 0:
                    self.BlackList.append(self.Whole_PS_With_Hash_Table[f])
        else:
            self.BlackList = self.Whole_PS_With_Hash_Table

        for f in range(0,len(self.BlackList)):
            self.SuspectTable.addItem(self.BlackList[f][1])

    def click_suspected_process_box(self):
        self.viroustotal_API_Result.clear()
        self.viroustotal_API.clear()
        print("[log] Clicked"+"__clicked_suspected_process_box___"+self.SuspectTable.currentItem().text())
        Suspect_Hash = []
        for f in range(0,len(self.Whole_PS_With_Hash_Table)):
            if self.SuspectTable.currentItem().text() == self.Whole_PS_With_Hash_Table[f][1]:
                Suspect_Hash.append(self.Whole_PS_With_Hash_Table[f][0])
        for f in range(0,len(Suspect_Hash)):
            self.viroustotal_API.addItem("[Number"+str(f+1)+" Hash: "+Suspect_Hash[f]+"]")
            self.Check_Hash_return_data = rs.Check_Hash.Response_of_Hash(Suspect_Hash[f])
            vaccine_list = sorted(list(self.Check_Hash_return_data.keys()))
            for f in range(0,len(vaccine_list)):
                self.viroustotal_API.addItem(str(f+1)+". "+vaccine_list[f])
            self.viroustotal_API.addItem("\n")

    def click_file_open_btn(self):
        print("[log] change txt_box")

    def click_list_of_vaccines_box(self):
        click_value = self.viroustotal_API.currentItem().text()
        print("[log] Clicked"+"__clicked_vaccine_box___"+click_value)
        result_table = self.Check_Hash_return_data
        result = result_table[click_value[click_value.find(' ')+1:]]
        result = json.dumps(
            result,
            indent=2
        )
        result = '%s' %result
        self.viroustotal_API_Result.addItem(
            "["+
            self.viroustotal_API.currentItem().text()+"]\n"+
            result
        )

    def Auto_refresh(self):
        print("[log] Refresh")
        if(self.count!=0):
            self.click_btn1()
            self.indices_list_click()

    def onButtonClicked(self):
        rs.openWhitelist.to_make_whitelist_in_local_directory('./',self.WhiteList)
        QMessageBox.about(self, "Success", "Success to export Whitelist")







