import os 
import sys
import pandas as pd
import numpy as np
import can
import json
from sklearn.tree import DecisionTreeClassifier, export_graphviz
from sklearn.model_selection import train_test_split
from joblib import dump, load
import queue
pd.options.mode.chained_assignment = None

def Preprocessing():
    with open("./logs/dos.log","r") as file:
        lines = file.read().splitlines()
        for i in range(len(lines)):
            lines[i] = lines[i].replace(" ",",")
            lines[i] = lines[i].replace("#",",")
            lines[i] = lines[i].replace("(","")
            lines[i] = lines[i].replace(")","")
            lines[i] = lines[i].split(",")
            lines[i][2] = int(lines[i][2], 16)
            chunk, chunk_size = len(lines[i][3]), 2
            x = [int(lines[i][3][j:j+chunk_size], 16) for j in range(0, chunk, chunk_size)]
            del lines[i][3]
            lines[i] = lines[i] + x
            lines[i][0] = float(lines[i][0])
            if lines[i][2] != 0: # beingn
                lines[i].append(int(0))
            else:                # malicious
                lines[i].append(int(1))
        for i in range(1,len(lines)):
            lines[len(lines)-i][0] = lines[len(lines)-i][0] - lines[len(lines)-i-1][0]
        df = pd.DataFrame(lines)
        df.fillna(0, inplace=True)
        df.drop([1], axis=1, inplace=True)
        df.drop([0,len(df.index)-1], axis=0, inplace=True)
        df.to_csv("./Preprocessing_log2csv/dos.csv", index=False, header=False)
    
    with open("./logs/Spoofing_steer.log","r") as file:
        lines = file.read().splitlines()
        for i in range(len(lines)):
            lines[i] = lines[i].replace(" ",",")
            lines[i] = lines[i].replace("#",",")
            lines[i] = lines[i].replace("(","")
            lines[i] = lines[i].replace(")","")
            lines[i] = lines[i].split(",")
            lines[i][2] = int(lines[i][2], 16)
            chunk, chunk_size = len(lines[i][3]), 2
            x = [int(lines[i][3][j:j+chunk_size], 16) for j in range(0, chunk, chunk_size)]
            del lines[i][3]
            lines[i] = lines[i] + x
            lines[i][0] = float(lines[i][0])
            if lines[i][2] == 485 and lines[i][3:] == [00,227,1,00,00,00,00,00]: # malicious
                lines[i].append(int(1))
            else:                # beingn
                lines[i].append(int(0))
        for i in range(1,len(lines)):
            lines[len(lines) - i][0] = lines[len(lines) - i][0] - lines[len(lines) -i-1][0]
        df = pd.DataFrame(lines)
        df.fillna(0, inplace=True)
        df.drop([1], axis=1, inplace=True)
        df.drop([0,len(df.index)-1], axis=0, inplace=True)
        df.to_csv("./Preprocessing_log2csv/Spoofing_steer.csv", index=False, header=False)

    with open("./logs/normal.log","r") as file:
        lines = file.read().splitlines()
        for i in range(len(lines)):
            lines[i] = lines[i].replace(" ",",")
            lines[i] = lines[i].replace("#",",")
            lines[i] = lines[i].replace("(","")
            lines[i] = lines[i].replace(")","")
            lines[i] = lines[i].split(",")
            lines[i][2] = int(lines[i][2], 16)
            chunk, chunk_size = len(lines[i][3]), 2
            x = [int(lines[i][3][j:j+chunk_size], 16) for j in range(0, chunk, chunk_size)]
            del lines[i][3]
            lines[i] = lines[i] + x
            lines[i][0] = float(lines[i][0])
            # if lines[i][2] == 485 and lines[i][3:] == [00,227,1,00,00,00,00,00]: # malicious
            #     lines[i].append(int(1))
            # else:                # beingn
            #     lines[i].append(int(0))
        for i in range(1,len(lines)):
            lines[len(lines) - i][0] = lines[len(lines) - i][0] - lines[len(lines) -i-1][0]
        df = pd.DataFrame(lines)
        df.fillna(0, inplace=True)
        df.drop([1], axis=1, inplace=True)
        df.drop([0,len(df.index)-1], axis=0, inplace=True)
        df.to_csv("./Preprocessing_log2csv/normal.csv", index=False, header=False)

def Training():
    with open('./Preprocessing_log2csv/dos.csv', newline='') as csvfile:
        rows = pd.read_csv(csvfile,header=None)
        y = rows[10]
        x = rows.drop([10], axis=1)
        X_train, X_test, y_train, y_test = train_test_split(x, y , test_size=0.3)
    
    if not os.path.exists("./models"):
        os.mkdir("./models")

    model = DecisionTreeClassifier()
    model.fit(X_train, y_train)
    print(model.score(X_test, y_test))
    dump(model, './models/Dos_DT.joblib')

    with open('./Preprocessing_log2csv/Spoofing_steer.csv', newline='') as csvfile:
        rows = pd.read_csv(csvfile,header=None)
        y = rows[10]
        x = rows.drop([10], axis=1)
        X_train, X_test, y_train, y_test = train_test_split(x, y , test_size=0.3)
    
    if not os.path.exists("./models"):
        os.mkdir("./models")

    model = DecisionTreeClassifier()
    model.fit(X_train, y_train)
    print(model.score(X_test, y_test))
    dump(model, './models/Spoofing_DT.joblib')

def Testing():
    with open('./Preprocessing_log2csv/normal.csv', newline='') as csvfile:
        df = pd.read_csv(csvfile,header=None)
        model_DoS = load('./models/Dos_DT.joblib')
        model_Spoofing = load('./models/Spoofing_DT.joblib')
        result = []
        for i in range(len(df.index)):
            result.append(model_Spoofing.predict(np.array(df.loc[i][0:10]).reshape(1,-1)) == 1)
            if model_DoS.predict(np.array(df.loc[i][0:10]).reshape(1,-1)) == 1:
                print("ids classification Error")
        # df[12] = result
        # df.to_csv("./Preprocessing_log2csv/DoS_normal.csv",index=False,header=False)

    
def CAN_ids():

    bus = can.interface.Bus(channel= 'vcan0', bustype = 'socketcan')
    print("Initializing CANbus")
    
    # load model
    model_DoS = load('./models/Dos_DT.joblib')
    model_Spoofing = load('./models/Spoofing_DT.joblib')

    # read bus in loop
    while 1:
        msg_buffer = queue.Queue(maxsize=10)
        msg_dlc = queue.Queue(maxsize=10)
        for msg in bus:
            msg_buffer.put(msg.data.hex())
            msg_dlc.put(msg.dlc)
            msg_h = msg_buffer.get()
            dlc = msg_dlc.get()

            msg_list = []
            msg_data_field = []
            msg_list.append(msg.timestamp)
            msg_list.append(msg.arbitration_id)
            for i in range(0, dlc*2, 2):
                msg_data_field.append(int(msg_h[i:i+2], 16))
            if dlc != 8:     # alignment
                for i in range(8-dlc):
                    msg_data_field.append(int(0))
            msg_list = msg_list + msg_data_field


            # Dict to JSON fromat
            # {"Timestamp": time, "ID": id,"Classification": Benign | Malicious ,"Attack_type": DoS | Spoofing}
            
            report_msg = {}     
            report_msg.update({'Timestamp':msg.timestamp})
            report_msg.update({'ID':msg.arbitration_id})

            if model_DoS.predict(np.array(msg_list).reshape(1,-1)) == 0 and model_Spoofing.predict(np.array(msg_list).reshape(1,-1)) == 0:
                report_msg.update({'Classification':'Benign'})

            elif model_DoS.predict(np.array(msg_list).reshape(1,-1)) != 0:
                report_msg.update({'Classification':'Malicious'})
                report_msg.update({'Attack_type':'DoS'})
            
            elif model_Spoofing.predict(np.array(msg_list).reshape(1,-1)) != 0:
                report_msg.update({'Classification':'Malicious'})
                report_msg.update({'Attack_type':'Spoofing'})

            json_msg = json.dumps(report_msg)
            print(json_msg)

            # send json_msg by socketIO
    

def main():
    Preprocessing()
    Training()
    #Testing()
    CAN_ids()


if __name__ == '__main__':
    main()
