import pandas as pd
from datetime import datetime

# Read Data From Source File 'log.txt'

LOG_OUTPUT = '.\log_output'
LOG_INPUT = '.\log_input\log.txt'

df = pd.read_table(LOG_INPUT, delimiter=' ', usecols=range(0, 8), header=None, encoding = 'ISO-8859-1', low_memory=False) 

# Drop Invalid Columns
df.drop([1,2,4],axis=1,inplace=True)

# Rename Column Names
df.columns = ['Host', 'Time','Resource','HTTP Reply Code','Bytes']

# Replace '-' in the Bytes Column to 0 bytes
df['Bytes'].replace('-',0, inplace=True)

# Remove '[' from Timestamp
df['Time'] = df['Time'].str.lstrip('[')

# Split Timestamp data at first instance of ':'
df['Time'] = df['Time'].apply(lambda x: x.split(':',1))

# Join Timestamp Data such that it's separated by 1 whitespace
df['Time'] = df['Time'].apply(lambda x: " ".join(x))

# Modify Data in 'Resource' column to reflect oly the 'Resource' File Path
#df['Resource'] = df['Resource'].apply(lambda x: x.split(' ')[1])

# Convert 'Timestamp' column type to Date Time format
df['Time'] = df['Time'].apply(pd.to_datetime)

# Convert 'Bytes' column type to Numeric Value
df['Bytes'] = df['Bytes'].apply(pd.to_numeric, errors='coerce')

# Convert 'HTTP Reply Code'' column type to Numeric Value
df['HTTP Reply Code'] = df['HTTP Reply Code'].apply(pd.to_numeric, errors='coerce')

# Add Time Zone to Time Stamp
#df['Time'].apply(lambda x : x.tz_localize('US/Eastern'))
#df.head()

#Feature 1:
#List the top 10 most active Host/IP addresses that have accessed the site.

TOP_10_HOST = df['Host'].value_counts().head(10)

# Write Top 10 Host/IP addresses that have accessed the site to file

TOP_10_HOST.to_csv('LOG_OUTPUT/hosts.txt', index=True)

#Feature 2:
#Identify the 10 resources that consume the most bandwidth on the site

BYTES = df.groupby(['Resource'])['Bytes'].sum()
RESOURCE = df.groupby(['Resource'])['Resource'].count()
TOP_10_BW = (BYTES * RESOURCE).sort_values(ascending = False).head(10) 

# Write Top 10 Resources that consumes highest Bandwidth to file

resources = open("LOG_OUTPUT/resources.txt",'w')

for key,value in TOP_10_BW.iteritems():
    resources_output = ''.join([key.split(" ")[1],'\n'])
    resources.write(resources_output)
    
resources.close()

#Feature 3:
#List the top 10 busiest (or most frequently visited) 60-minute periods

df.index = df['Time']
end_time = df['Time'].max()
start_time = df['Time'].min()

current_time = start_time
total_time_interval = (end_time - start_time).total_seconds() 

total_time_interval = int(total_time_interval) + 1
end_time = current_time + pd.Timedelta(seconds=3600)

visited_map = {}

for i in range(total_time_interval):
    
    visited_count = df[(df['Time'] >= start_time) & (df['Time'] <= end_time)].count()['Host']    
    
    date_f = start_time.strftime('%d/%b/%Y:%H:%M:%S -0400')
    
    visited_map[date_f] = visited_count
    start_time = start_time + pd.Timedelta(seconds=1)
    end_time = start_time + pd.Timedelta(seconds=3600)   

# Write Top 10 60 minute interval of high site access to file 

hours_access = open("LOG_OUTPUT/hours.txt",'w')

i = 0

for key,value in sorted(visited_map.items(),reverse = False):

    i += 1
    if(i>10):        
        break
    
    hours_output = ("".join([key,',',str(value),'\n']))
    hours_access.write(hours_output)


#Feature 4:
#Detect patterns of three failed login attempts from the same IP address over 20 
#seconds so that all further attempts to the site can be blocked for 5 minutes. 
#Log those possible security breaches

host_unique = df['Host'].unique()
N = len(host_unique)

buffer = {}
max_attempt = 3
error_status = 401
wait_time_blocked = 300
wait_time_unblocked = 20

for i in range(N):
    
    buffer[host_unique[i]] = {}
    buffer[host_unique[i]]['attempt'] = 0    
    buffer[host_unique[i]]['wait_time'] = 0
    buffer[host_unique[i]]['blocked'] = False
    buffer[host_unique[i]]['total_wait_time'] = wait_time_unblocked
	
end_time = df['Time'].max()
start_time = df['Time'].min()

current_time = start_time
total_time = (end_time - start_time).total_seconds()

total_time = int(total_time) + 1
blocked_hosts = open("LOG_OUTPUT/blocked.txt",'w')

for i in range(total_time):       
    
    current_time_values = df[df['Time']==current_time]
    
    for _, j in current_time_values.iterrows():
        
        buffer[j['Host']]['wait_time'] += 1

        # Do When Not In Blocked State
        if buffer[j['Host']]['blocked'] == False:

            # Check for UnSuccessful Attempt
            if j['HTTP Reply Code'] == error_status:
                buffer[j['Host']]['attempt'] += 1
            
            # Goto Blocked State
            if buffer[j['Host']]['attempt'] == max_attempt:
                buffer[j['Host']]['total_wait_time'] = wait_time_blocked                  
                buffer[j['Host']]['blocked'] = True
                
            # Reset Timer of Host if Successful Transmission
            if buffer[j['Host']]['wait_time'] <= wait_time_unblocked and j['HTTP Reply Code'] != error_status:
                buffer[j['Host']]['attempt'] = 0    
                buffer[j['Host']]['wait_time'] = 0
                buffer[j['Host']]['blocked'] = False
                buffer[j['Host']]['total_wait_time'] = wait_time_unblocked
        
        else: 
            
            # LOG failed attempts in blocked state
            
            date_f = j['Time'].strftime('[%d/%b/%Y:%H:%M:%S -0400]')

            line_file_output = ''.join([j['Host'], ' - - ' , date_f, ' "', j['Resource'], '" ', 
                         str(j['HTTP Reply Code']), ' ', str(j['Bytes']),'\n'])

            blocked_hosts.write(line_file_output)
            
            # Come Out Of Blocked State
            if buffer[j['Host']]['wait_time'] ==  buffer[j['Host']]['total_wait_time']:
                
                buffer[j['Host']]['attempt'] = 0    
                buffer[j['Host']]['wait_time'] = 0
                buffer[j['Host']]['blocked'] = False
                buffer[j['Host']]['total_wait_time'] = wait_time_unblocked
   
    current_time = current_time + pd.Timedelta(seconds=1)
    
blocked_hosts.close()

#Feature 5
#List the Top 10 Busiest Hours

df.index = df['Time']
COUNT = df.groupby([df.index.date,df.index.hour]).size()
TIMESTAMP = df.groupby([df.index.date,df.index.hour]).nth(0)['Time']

TOP_10_BUSY_PERIOD = [TIMESTAMP, COUNT]
TOP_10_BUSY_PERIOD = pd.concat(TOP_10_BUSY_PERIOD, axis = 1)
TOP_10_BUSY_PERIOD.sort_values(by=[0], ascending = False).head(10) 
TOP_10_BUSY_PERIOD.to_csv('LOG_OUTPUT/hours_best.txt', sep=',', index=False, header=False, date_format='%d/%b/%Y:%H:%M:%S -0400')