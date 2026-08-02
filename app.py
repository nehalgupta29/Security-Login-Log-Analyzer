import streamlit as st
from datetime import datetime
import csv
import os
import pandas as pd
import plotly.express as px
import hashlib 


st.set_page_config(layout="wide")

#Session Var and Constants
if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False
if "current_user" not in st.session_state:
    st.session_state["current_user"] = ""
MEDIUM_THRESHOLD = 3
HIGH_THRESHOLD = 5
CRITICAL_THRESHOLD = 10
MIN_PASSWORD_LENGTH = 8
MIN_USERNAME_LENGTH = 5

#DATA STORAGE 
#load files
def load_authentication_data():
    file_path = "authentication_report.csv"
    if (os.path.exists(file_path)) and (os.path.getsize(file_path) != 0):
       df = pd.read_csv(file_path) 
    else:
        df = pd.DataFrame()
    return df 

def load_suspicious_data():
    file_path = "suspicious_report.csv"
    if (os.path.exists(file_path)) and (os.path.getsize(file_path) != 0):
       df = pd.read_csv(file_path) 
    else:
        df = pd.DataFrame()
    return df 

#Storing existing users from user csv file to dict 
def load_users():
    users = {}
    if os.path.exists("users.csv") and os.path.getsize("users.csv")>0:
        df = pd.read_csv("users.csv")
        users = df.set_index("Username")["Password"].to_dict()
    return users

#Storing registered users permanently 
def save_users(username,password):
    file_exists = os.path.exists("users.csv")
    with open("users.csv", "a", newline="") as file:
        writer = csv.writer(file)

        if (not file_exists) or os.path.getsize("users.csv") == 0:
            writer.writerow(
                ["Username","Password"]
            )
        hashed_pwd = hashlib.sha256(password.encode()).hexdigest()
        writer.writerow(
            [username, hashed_pwd]
        )

#Generate log report
def save_authentication_log(username, action, status, reason):
    file_exists = os.path.exists("authentication_report.csv")
    with open("authentication_report.csv", "a", newline="") as file:
        writer = csv.writer(file)

        now = datetime.now()
        formatted_now = now.strftime("%Y-%m-%d %H:%M:%S")

        if (not file_exists) or os.path.getsize("authentication_report.csv") == 0:
            writer.writerow(
                ["Timestamp", "Username", "Event Type", "Status", "Reason"]
            )

        writer.writerow(
            [formatted_now, username, action, status, reason]
        )
        update_suspicious_report(username)

#Generating suspicious users report
def save_suspicious_log(sus_users):
    with open("suspicious_report.csv", "a", newline="") as file:
        writer = csv.writer(file)
        file_empty = (not os.path.exists("suspicious_report.csv")) or (os.path.getsize("suspicious_report.csv") == 0)
        date = datetime.now().strftime("%Y-%m-%d")
        
        if file_empty:
            writer.writerow(
                ["Date","Username", "Failed Attempts", "Risk Level", "Reason","Recommended Action"]
            )
        
        for user,details in sus_users.items():
            if not file_empty:
                old_df = pd.read_csv("suspicious_report.csv")
                #to not repeat the users again and again 
                #only when hitting a specific level 
                already_exists = (
                    (old_df['Username'] == user) &
                    (old_df['Risk Level'] == details['risk_level'])
                ).any()

                if already_exists:
                    continue
            writer.writerow(
                [date,user, details["count"], 
                details["risk_level"],
                details["reason"],
                details["recommendation"]]
            )

#updating the report only when the specific threshold is hit
def update_suspicious_report(username):
    df = load_authentication_data()
    failed_attempts = len(df[(df["Username"] == username) & 
                                  (df["Event Type"] == "Login") & 
                                  (df["Status"] == "Failed")])
    risk_users = classify_risk()
    if failed_attempts >= MEDIUM_THRESHOLD:
        save_suspicious_log(risk_users)

#SECURITY ANALYSIS
def detect_suspicious_users():
    suspicious_users = {}

    df = load_authentication_data()
    if not df.empty:
        failed_df = df[(df["Event Type"] == "Login") & (df["Status"] == "Failed")]
        target_users = failed_df.groupby("Username").size()
        
        for user, count in target_users.items():
            if count >= 3:
                suspicious_users[user] = {"count": count}
    return suspicious_users
    
def classify_risk():
    suspicious_users = detect_suspicious_users()
    for user,detail in suspicious_users.items():
        count = detail["count"]

        if count >= MEDIUM_THRESHOLD and count < HIGH_THRESHOLD:
            risk_level = "Medium"
            reason = "Multiple Failed Login Attempts Detected"
            recommendation = "Monitor User Activity"
            
        elif count >= HIGH_THRESHOLD and count <= CRITICAL_THRESHOLD:
            risk_level = "High"
            reason = "Repeated Failed Authentication Attempts"
            recommendation = "Investigate Authentication Attempts"

        elif count > CRITICAL_THRESHOLD:
            risk_level = "Critical"
            reason = "Possible Brute Force Attack Detected"
            recommendation = "Lock Account and Investigate Immediately"

        suspicious_users[user].update({"risk_level": risk_level,
                                        "reason": reason,
                                        "recommendation": recommendation})
    return suspicious_users

def validate_registration(username,password,users):
    status = "Failed"
    reason = ""
    if not username :
        reason = "Username field empty"
    elif len(username) < MIN_USERNAME_LENGTH:
        reason = "Username Too Short (Min. length 5)"
    elif username in users:
        reason = "Username already exists"
    elif not password:
        reason = "Password field empty"
    elif len(password) < MIN_PASSWORD_LENGTH:
        reason = "Password Too Short (Min. length 8)"
    else:
        status = "Successful" 
        reason = "User Registered Successfully"
    return status, reason

def validate_login(username,password,users):
    status = "Failed"
    reason = ""
    hashed_pwd = hashlib.sha256(password.encode()).hexdigest()
    if username in users and users[username] == hashed_pwd:
        status = "Successful"
        reason = "Authentication Successful"
    else:
        if not username or not password:
            reason = "Empty Fields"
        elif username not in users:
            reason = "User Not Found"
        elif users[username] != hashed_pwd:
            reason = "Wrong Password"
    return status, reason


#Data Generating
#generating all the stats
def generate_stats():
    total_events = 0
    passed_login = 0
    failed_login = 0 
    reg_passed = 0 
    active_user = ""
    users = {}
    suspicious = 0
    try:
        auth_df = load_authentication_data()
        if not auth_df.empty:
            total_events = len(auth_df)
            group = auth_df.groupby("Event Type")["Status"].value_counts().unstack(fill_value=0)
            passed_login = group.get("Successful",pd.Series()).get("Login",0)
            failed_login = group.get("Failed",pd.Series()).get("Login",0)
            reg_passed = group.get("Successful",pd.Series()).get("Register",0)
            active_user = auth_df.groupby("Username").size().idxmax()
        else:
            reg_passed = 0
            active_user = "N/A"
        
        sus_df = load_suspicious_data()
        if not sus_df.empty:
            suspicious = len(sus_df)
            risk_order = pd.CategoricalDtype(
                            categories=["Medium", "High","Critical"],
                            ordered=True
                        )

            sus_df["Risk Level"] = sus_df["Risk Level"].astype(risk_order)


            failed_df = sus_df.groupby("Username")[["Failed Attempts","Risk Level"]].max()
            if len(failed_df) > 0:
                for user, row in failed_df.iterrows():
                    #to check data printing print(user,row)
                    if row['Failed Attempts'] > 5:
                        users[user] = {"Attempts": row["Failed Attempts"],
                                    "Risk_level": row["Risk Level"]
                                    } 
    except Exception as e:
        st.write(e)
    #to check wheather users was empty or not print("sus: ",users)
    return total_events,passed_login,failed_login,reg_passed,active_user,suspicious,users      

#All features 
def download_report():
    col1,col2 = st.columns(2)
    with col1:
        if os.path.exists("authentication_report.csv"):
            with open("authentication_report.csv") as file:
                st.download_button("📥 Authentication Report",
                                data=file,
                                file_name="authentication_report.csv",
                                mime="text/csv")
    with col2:
        if os.path.exists("suspicious_report.csv"):
            with open("suspicious_report.csv") as file:
                st.download_button("📥 Suspicious Report",
                                data=file,
                                file_name="suspicious_report.csv",
                                mime="text/csv")

def filter_user():
    users_dict = load_users()
    auth_df = load_authentication_data()
    sus_df = load_suspicious_data()
    users_list = ["Overall"] + list(users_dict.keys())
    
    select_user = st.selectbox("Search User:",users_list)
    if select_user == "Overall":
        filtered_auth_df = auth_df
        filtered_sus_df = sus_df
    elif select_user in users_list:
        filtered_auth_df = auth_df[auth_df["Username"]==select_user]
        filtered_sus_df = sus_df[sus_df["Username"]==select_user]
        total_events = len(auth_df[auth_df["Username"]==select_user])
        login_passed = len(auth_df[(auth_df["Username"]==select_user) & 
                            (auth_df["Event Type"] == "Login") &
                            (auth_df["Status"] == "Successful")])
        user_sus = sus_df[sus_df["Username"]==select_user]
        if user_sus.empty:
            risk = "N/A"

        else:
            login_failed = sus_df.loc[sus_df["Username"]==select_user ,
                            "Failed Attempts"].max()
            risk = sus_df.loc[sus_df["Username"]==select_user,
                        "Risk Level"].iloc[-1]
            #-1 bcause to get latest risk level incase of multiple entries

        

        st.info(f"""
            ### User Summary

            **Username:** {select_user}

            **Total Events:** {total_events}

            **Successful Logins:** {login_passed}

            **Failed Logins:** {login_failed}

            **Risk Level:** {risk}
        """)
        
    else:
        st.error(f"{select_user} Not Found!!")
    return filtered_auth_df, filtered_sus_df,select_user


#all the important charts shown in dashboard
def authentication_charts(auth_df,passed_login,failed_login):
    login_df = pd.DataFrame({
        "Event": ["Successful Login","Failed Login"],
        "Count": [passed_login,failed_login]
    })

    
    failed_df = auth_df[(auth_df["Event Type"] == "Login") & 
                (auth_df["Status"] == "Failed")].copy()
    if failed_df.empty:
        st.info("No failed login attempts.")
        return

    failed_df["Timestamp"] = pd.to_datetime(failed_df["Timestamp"])
    failed_df["Day"] = failed_df["Timestamp"].dt.day_name()
    failed_df["Hour"] = failed_df["Timestamp"].dt.hour
    
    
    heatmap_df = pd.crosstab(failed_df["Day"],failed_df["Hour"])
    heatmap_df = heatmap_df.reindex(["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"],
                     fill_value=0)
    
    heatmap_df = heatmap_df.reindex(columns=list(range(24)),
                     fill_value=0)


    
    col1,col2 = st.columns(2,gap = "large")
    
    with col1:
        fig = px.bar(login_df,x="Count",y="Event",
                orientation="h",
                text="Count"
            )
        fig.update_layout(
            title="Login Success vs Failed",
            xaxis_title="Number of Logins",
            yaxis_title="",
            height=350,
            template="plotly_dark"
        )
        st.plotly_chart(fig,use_container_width=True)
    with col2:
        fig = px.imshow(heatmap_df,
                        color_continuous_scale="Reds")
        fig.update_xaxes(
            tickmode="linear",
            tick0=0,
            dtick=1
        )
        
        fig.update_layout(
            title="Failed Login Heatmap",
            xaxis_title="Hour of Day",
            yaxis_title="Day of Week",
            height=400,
            template="plotly_dark"
        )
        fig.update_traces(
            text=heatmap_df.values, 
            texttemplate="%{text}",
            textfont={"size":14,"color":"black"}
        )
        st.plotly_chart(fig,use_container_width=True)

def risk_chart(auth_df,sus_df):
    failed_df = auth_df[(auth_df["Event Type"] == "Login") & 
                (auth_df["Status"] == "Failed")].copy()
    if failed_df.empty:
        st.info("No failed login attempts found.")
        return
    if sus_df.empty:
        st.info("No suspicious users detected.")
        return
    failed_df["Timestamp"] = pd.to_datetime(failed_df["Timestamp"])
    failed_df["week"] = failed_df["Timestamp"].dt.to_period("w").astype(str)
    
    col1,col2 = st.columns(2,gap = "large")
    
    with col1:
        select_week = st.selectbox("Select week",failed_df["week"].unique())
        week_df = failed_df[failed_df["week"] == select_week].copy()
        week_df["Day"] = week_df["Timestamp"].dt.day_name()

        weekday_data = (week_df.groupby("Day")
                     .size()
                     .reindex(["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"],
                     fill_value=0).reset_index(name="Failed Logins"))
        fig = px.line(weekday_data,x="Day",y="Failed Logins")
        fig.update_layout(
            title=f"Failed Logins ({select_week})",
            height=350,
            template="plotly_dark"
        )
        st.plotly_chart(fig,use_container_width=True)


    with col2:
        risk_df = sus_df["Risk Level"].value_counts().reset_index(name="Frequency")

        fig = px.bar(risk_df,x = "Frequency",y="Risk Level",
                     orientation="h",
                    text="Frequency")
        fig.update_layout(
            title="Risk Level Distribution",
            xaxis_title="Number of Failed Events",
            yaxis_title="",
            height=350,
            template="plotly_dark"
        )

        st.plotly_chart(fig,use_container_width=True)

#Latest data section
def latest_data(auth_df, suspicious,users,select_user):

    st.divider()
    col1,col2 = st.columns(2,gap="large")
    with col1:
        st.markdown("""
                <br><h1>📝 Latest Authentication Logs</h1>
            """,unsafe_allow_html=True)
        if auth_df.empty:
            st.write("No Authentication log.")
        else:
            st.write(auth_df.tail(5))

    with col2:
        if select_user == "Overall" and users and suspicious != 0:
            st.markdown("""
                <br><h2>Most Suspicious users:</h2>
            """,unsafe_allow_html=True)
            for user,detail in users.items():
                st.info(f"{user} --> {detail['Risk_level']} risk ----> ({detail['Attempts']} attempts)")
        else:
            st.info("No Suspicious users")



#UI 
#Dashboard section of the web 
def dashboard():
    total_events,passed_login,failed_login,reg_passed,active_user,suspicious,users = generate_stats()
    
    col1,col2,col3,col4=st.columns([5,4,1,1])

    with col1:
        st.title("SECURITY DASHBOARD")
    st.caption(
        "Real-time authentication monitoring dashboard for analyzing login events,"
        "detecting suspicious users, and visualizing security risks."
    )
    with col2:
        download_report()

    with col3:
        if st.button("🔄 Refresh"):
            st.rerun()

    with col4:
        if st.button("🚪 Logout"):
            st.session_state["logged_in"]=False
            st.session_state["current_user"]=""
            st.rerun()

    col1,col2,col3 = st.columns(3,gap="large")
    col4,col5,col6 = st.columns(3,gap="large")
    
    with col1:
        with st.container(border=True):
            st.metric(label=" 📄 Total Events ",value=total_events)
    with col2:
        with st.container(border=True):
            st.metric(label=" ✅ Successful Logins ",value=passed_login)
    with col3:
        with st.container(border=True):
            st.metric(label=" ❌ Failed Logins ",value=failed_login)
    with col4:
        with st.container(border=True):
            st.metric(label=" Successful Registration ",value=reg_passed)
    with col5:
        with st.container(border=True):
            st.metric(label=" 👤 Most Active User ",value=active_user)
    with col6:
        with st.container(border=True):
            st.metric(label=" 🚨 Suspicious Accounts ",value=suspicious)
    
    st.divider()

    filtered_auth_df,filtered_sus_df, select_user= filter_user()
    passed_login = len(filtered_auth_df[
    (filtered_auth_df["Event Type"]=="Login") &
    (filtered_auth_df["Status"]=="Successful")
    ])

    failed_login = len(filtered_auth_df[
        (filtered_auth_df["Event Type"]=="Login") &
        (filtered_auth_df["Status"]=="Failed")
    ])

    st.divider()
    st.markdown("""
                <br><h1>📊 Authentication Analytics</h1>
    """,unsafe_allow_html=True)
    authentication_charts(filtered_auth_df,passed_login,failed_login)

    st.divider()

    st.markdown("""
                <br><h1>📊 Threat Analysis</h1>
    """,unsafe_allow_html=True)
    risk_chart(filtered_auth_df,filtered_sus_df)
    
    latest_data(filtered_auth_df,suspicious, users,select_user)

    st.divider()

    st.markdown(
    """
    <div style='text-align:center;color:gray;font-size:14px;'>

    Security Login Simulator

    Built using <b>Python • Streamlit • Pandas • Plotly</b>

    Developed for Educational Purposes

    </div>
    """,
    unsafe_allow_html=True
    )
    

#Suspicious User section of the web 
def sus_users():
    sus_df = load_suspicious_data() 
    if not sus_df.empty:
        st.write("Suspicious User Report")
        st.write(sus_df)
    else:
        st.write("No Suspicious Users Detected.")
    


    if st.sidebar.button("Logout"):
        st.session_state["logged_in"] = False
        st.session_state["current_user"] = ""

#Resgitration part of web
def registration_page(username,password,users):
    status, reason = validate_registration(username,password,users)
    if status == "Failed":
        st.error(reason)
        save_authentication_log(username, action, status, reason)
    else:
        save_users(username,password)
        st.success(reason)
        save_authentication_log(username, action, status, reason)

#Login part of the web
def login_page(username,password,users):
    status, reason = validate_login(username,password,users)
    if status == "Failed":
        st.error("Login Failed")
        st.error(reason)
        st.write("Access Denied.")
        save_authentication_log(username, action, status, reason)
    else:
        st.success("Login Successful")
        st.write(f"Welcome, {username}!")
        st.write("Access Granted.")
        st.session_state["logged_in"] = True
        st.session_state["current_user"] = username
        save_authentication_log(username, action, status, reason)

st.sidebar.title("🛡 Security System")
st.sidebar.markdown("---")

page = st.sidebar.radio("Menu",["Authentication","Dashboard (admin only)",
                                "Suspicious Users (admin only)"]) 
st.sidebar.markdown("---")

if st.session_state["logged_in"]:
    st.sidebar.success(
        f"Logged in as\n\n{st.session_state['current_user']}"
    )
else:
    st.sidebar.warning("Not Logged In")

#Web Application 
st.title("Security Login Simulator & Log Analyzer")
if page == "Authentication":
    with st.form("Login_form"):
        st.header("User Authentication System")
        st.subheader("Simulate login attempts and generate security events for future analysis")

        action = st.radio("Select your action: ",["Register","Login"])
        
        username = st.text_input("Username: ")
        password = st.text_input("Password: ",type="password")
        
        submitted = st.form_submit_button("Submit")

        if submitted:
            users = load_users()
            if action == "Login":
                login_page(username,password,users)
            else:
                registration_page(username,password,users)

            st.write("Report Generated Successfully")
        

elif page == "Dashboard (admin only)":
    if not st.session_state["logged_in"]:
        st.warning("Please Login First.")
        #warning issue
    elif st.session_state["current_user"] != "admin_25":
        st.error("Access Denied: Admin privileges required.")
        #access denied
    else:
        #dashboard view
        dashboard()

else:
    if not st.session_state["logged_in"]:
        st.warning("Please Login First.")
        #warning issue
    elif st.session_state["current_user"] != "admin_25":
        st.error("Access Denied: Admin privileges required.")
        #access denied
    else:
        #suspicious view
        sus_users()    
