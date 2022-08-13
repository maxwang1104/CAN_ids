
An ids project cooperate with MIT x Cycraft x NYCU

# ML-CAN IDS

An intusion detection system designed in machine learning to recognize the malicious message appear on CAN bus

# Install all the neccessary software requirement:

```jsx
$pip install -r requirements.txt
```

# Create virtual CAN bus

```jsx
$sudo modprobe vcan
$sudo ip link add dev vcan0 type vcan
$sudo ip link set up vcan0
```

# Testing CAN ids

1. Test whether can_ids can catch **“DoS” attack**
    1. First, open a termonal to run python code
    
    ```jsx
    $python can_ids.py
    ```
    
      b.  Then, open another terminal to replay log file
    
    ```jsx
    $canplayer -I "dos.log" vcan0
    ```
    
      c.  Get the json msg like below
    
    ```python
    {'Timestamp': 1660372313.4541366, 'ID': 0, 'Classification': 'Malicious', 'Attack_type': 'DoS'}
    ```
    
2. Test whether can_ids can catch **“Spoofing” attack** → **Cycraft given dataset of Spoofing is wierd**
    
    (I assume msg can0 1E5#00FE7C0000000000 is Spoofing data)
    
    1. First, open a termonal to run python code
    
    ```jsx
    $python can_ids.py
    ```
    
      b.  Then, open another terminal to replay log file
    
    ```jsx
    $canplayer -I "Spoofing_steer.log" vcan0
    ```
    
      c.  Get the json msg like below
    
    ```python
    {'Timestamp': 1660377236.4955213, 'ID': 485, 'Classification': 'Malicious', 'Attack_type': 'Spoofing'}
    ```
    

# Data Format

```python
{"Timestamp": time, "ID": id,"Classification": Benign | Malicious ,"Attack_type": DoS | Spoofing}
```
