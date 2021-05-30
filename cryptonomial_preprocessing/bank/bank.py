import numpy as np
import pandas as pd

df = pd.read_csv('bank_full_processed.csv')

df.job = pd.Categorical(df.job)
df['job_code'] = df.job.cat.codes

df.marital = pd.Categorical(df.marital)
df['marital_status_code'] = df.marital.cat.codes

df.education = pd.Categorical(df.education)
df['education_code'] = df.education.cat.codes

df.default = pd.Categorical(df.default)
df['default_code'] = df.default.cat.codes

df.housing = pd.Categorical(df.housing)
df['housing_code'] = df.housing.cat.codes

df.loan = pd.Categorical(df.loan)
df['loan_code'] = df.loan.cat.codes

df.contact = pd.Categorical(df.contact)
df['contact_code'] = df.contact.cat.codes

df.month = pd.Categorical(df.month)
df['month_code'] = df.month.cat.codes

df.poutcome = pd.Categorical(df.poutcome)
df['poutcome_code'] = df.poutcome.cat.codes

df.y = pd.Categorical(df.y)
df['y_code'] = df.y.cat.codes

df = df.drop(['job', 'marital', 'education', 'default', 'housing', 'loan', 'contact', 'month', 'poutcome', 'y'], axis=1)

df.to_csv('bank_full_numeric.csv', index=False)


from sklearn import preprocessing

x = df.values #returns a numpy array
min_max_scaler = preprocessing.MinMaxScaler()
x_scaled = min_max_scaler.fit_transform(x)
df = pd.DataFrame(x_scaled)


df.to_csv('bank_full_normalized_numeric.csv', index=False)
