import numpy as np
import pandas as pd

df = pd.read_csv('census_processed.csv')

df.work = pd.Categorical(df.work)
df['work_code'] = df.work.cat.codes

df.education = pd.Categorical(df.education)
df['education_code'] = df.education.cat.codes

df.marital = pd.Categorical(df.marital)
df['marital_status_code'] = df.marital.cat.codes

df.occupation = pd.Categorical(df.occupation)
df['occupation_code'] = df.occupation.cat.codes

df.relationship = pd.Categorical(df.relationship)
df['relationship_code'] = df.relationship.cat.codes

df.race = pd.Categorical(df.race)
df['race_code'] = df.race.cat.codes

df.sex = pd.Categorical(df.sex)
df['sex_code'] = df.sex.cat.codes

df.naive_country = pd.Categorical(df.naive_country)
df['naive_country_code'] = df.naive_country.cat.codes

df.salary = pd.Categorical(df.salary)
df['salary_code'] = df.salary.cat.codes

df = df.drop(['work', 'marital', 'education', 'occupation', 'relationship', 'race', 'sex', 'naive_country', 'salary'], axis=1)

df.to_csv('census_numeric.csv', index=False)


from sklearn import preprocessing

x = df.values #returns a numpy array
min_max_scaler = preprocessing.MinMaxScaler()
x_scaled = min_max_scaler.fit_transform(x)
df = pd.DataFrame(x_scaled)


df.to_csv('census_normalized_numeric.csv', index=False)
