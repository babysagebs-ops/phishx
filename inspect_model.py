import pickle
import traceback

with open('pickle/model.pkl', 'rb') as f:
    try:
        obj = pickle.load(f)
        print(type(obj))
        print(obj)
    except Exception as e:
        traceback.print_exc()
