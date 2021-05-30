import numpy as np
import pandas as pd

df = pd.read_csv('ticdata2000_processed.csv')


df.to_csv('ticdata2000_processed_numeric.csv', index=False)


from sklearn import preprocessing

x = df.values #returns a numpy array
min_max_scaler = preprocessing.MinMaxScaler()
x_scaled = min_max_scaler.fit_transform(x)
df = pd.DataFrame(x_scaled)


df.to_csv('ticdata2000_processed_normalized_numeric.csv', index=False)
