import streamlit as st
import pandas as pd
import os
import gzip
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime
import plotly.express as px

# Set page config for a premium feel
st.set_page_config(
    page_title="DMARC Report Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for a clean, premium look
st.markdown("""
<style>
    .main {
        background-color: #f8f9fa;
    }
    .stMetric {
        background-color: white;
        padding: 1.5rem;
        border-radius: 0.5rem;
        box-shadow: 0 0.15rem 1.75rem 0 rgba(58, 59, 69, 0.15);
        border-left: 0.25rem solid #4e73df;
    }
    h1, h2, h3 {
        color: #1a1c20;
    }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ DMARC Report Analyzer")
st.markdown("Upload DMARC aggregate reports to parse and combine them.")

def parse_dmarc_xml(xml_content):
    root = ET.fromstring(xml_content)
    
    metadata = root.find('report_metadata')
    org_name = metadata.find('org_name').text if metadata is not None else "Unknown"
    report_id = metadata.find('report_id').text if metadata is not None else "Unknown"
    
    date_range = metadata.find('date_range')
    begin_date = ""
    end_date = ""
    if date_range is not None:
        begin_date = datetime.fromtimestamp(int(date_range.find('begin').text)).strftime('%Y-%m-%d %H:%M:%S')
        end_date = datetime.fromtimestamp(int(date_range.find('end').text)).strftime('%Y-%m-%d %H:%M:%S')

    policy_pub = root.find('policy_published')
    p_domain = policy_pub.find('domain').text if policy_pub is not None and policy_pub.find('domain') is not None else ""
    p_adkim = policy_pub.find('adkim').text if policy_pub is not None and policy_pub.find('adkim') is not None else ""
    p_aspf = policy_pub.find('aspf').text if policy_pub is not None and policy_pub.find('aspf') is not None else ""
    p_p = policy_pub.find('p').text if policy_pub is not None and policy_pub.find('p') is not None else ""
    p_sp = policy_pub.find('sp').text if policy_pub is not None and policy_pub.find('sp') is not None else ""
    p_pct = policy_pub.find('pct').text if policy_pub is not None and policy_pub.find('pct') is not None else ""

    records = []
    for record in root.findall('record'):
        row = record.find('row')
        source_ip = row.find('source_ip').text if row is not None else ""
        count = int(row.find('count').text) if row is not None else 0
        
        policy_evaluated = row.find('policy_evaluated')
        disposition = policy_evaluated.find('disposition').text if policy_evaluated is not None else "none"
        dkim_eval = policy_evaluated.find('dkim').text if policy_evaluated is not None else "fail"
        spf_eval = policy_evaluated.find('spf').text if policy_evaluated is not None else "fail"
        
        # Extract override reasons
        reasons = []
        if policy_evaluated is not None:
            for reason in policy_evaluated.findall('reason'):
                r_type = reason.find('type').text if reason.find('type') is not None else ""
                if r_type:
                    reasons.append(r_type)
        reasons_str = ", ".join(reasons) if reasons else "None"
        
        identifiers = record.find('identifiers')
        header_from = identifiers.find('header_from').text if identifiers is not None else ""
        
        records.append({
            'Org Name': org_name,
            'Report ID': report_id,
            'Begin Date': begin_date,
            'End Date': end_date,
            'Source IP': source_ip,
            'Count': count,
            'Disposition': disposition,
            'DKIM Eval': dkim_eval,
            'SPF Eval': spf_eval,
            'Override Reason': reasons_str,
            'Header From': header_from,
            'Policy Domain': p_domain,
            'Policy adkim': p_adkim,
            'Policy aspf': p_aspf,
            'Policy p': p_p,
            'Policy sp': p_sp,
            'Policy pct': p_pct
        })
        
    return records

def load_data(uploaded_files):
    all_records = []
    files_processed = 0
    for file in uploaded_files:
        filename = file.name
        if filename.endswith('.xml.gz') or filename.endswith('.gz'):
            try:
                with gzip.GzipFile(fileobj=file) as f:
                    xml_content = f.read()
                    all_records.extend(parse_dmarc_xml(xml_content))
                    files_processed += 1
            except Exception as e:
                st.error(f"Error parsing {filename}: {e}")
        elif filename.endswith('.zip'):
            try:
                with zipfile.ZipFile(file) as z:
                    for name in z.namelist():
                        if name.endswith('.xml'):
                            with z.open(name) as f:
                                xml_content = f.read()
                                all_records.extend(parse_dmarc_xml(xml_content))
                                files_processed += 1
            except Exception as e:
                st.error(f"Error parsing {filename}: {e}")
    return pd.DataFrame(all_records), files_processed

uploaded_files = st.file_uploader("Upload DMARC Report Files", type=['zip', 'gz'], accept_multiple_files=True)

if uploaded_files:
    df, files_count = load_data(uploaded_files)
else:
    df = pd.DataFrame()
    files_count = 0

if not df.empty:
    # Sidebar filters
    st.sidebar.header("Filters")
    orgs = ["All"] + list(df['Org Name'].unique())
    selected_org = st.sidebar.selectbox("Filter by Reporter Org", orgs)
    
    filtered_df = df
    if selected_org != "All":
        filtered_df = df[df['Org Name'] == selected_org]
        
    reports = ["All"] + list(filtered_df['Report ID'].unique())
    selected_report = st.sidebar.selectbox("Filter by Report ID", reports)
    
    if selected_report != "All":
        filtered_df = filtered_df[filtered_df['Report ID'] == selected_report]
        
    # Metrics
    total_emails = filtered_df['Count'].sum()
    unique_ips = filtered_df['Source IP'].nunique()
    
    passed_df = filtered_df[(filtered_df['SPF Eval'] == 'pass') & (filtered_df['DKIM Eval'] == 'pass')]
    passed_emails = passed_df['Count'].sum()
    pass_rate = (passed_emails / total_emails * 100) if total_emails > 0 else 0
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Emails Analyzed", f"{total_emails:,}")
    with col2:
        st.metric("Unique IP Addresses", f"{unique_ips:,}")
    with col3:
        st.metric("Overall Pass Rate", f"{pass_rate:.1f}%")
    with col4:
        st.metric("Reports Processed", f"{files_count}")

    # Show Published Policy
    st.subheader("📋 Published Policy")
    if selected_report != "All" and not filtered_df.empty:
        report_data = filtered_df.iloc[0]
        col_p1, col_p2, col_p3, col_p4, col_p5, col_p6 = st.columns(6)
        col_p1.metric("Domain", report_data['Policy Domain'])
        col_p2.metric("adkim", report_data['Policy adkim'])
        col_p3.metric("aspf", report_data['Policy aspf'])
        col_p4.metric("p", report_data['Policy p'])
        col_p5.metric("sp", report_data['Policy sp'])
        col_p6.metric("pct", report_data['Policy pct'])
    else:
        st.info("Select a specific Report ID from the sidebar to view its published policy.")

    # Layout
    col_left, col_right = st.columns([2, 1])
    
    with col_left:
        st.subheader("📋 Combined Report Data")
        st.dataframe(filtered_df, use_container_width=True)
        
    with col_right:
        st.subheader("📊 Top Sources")
        ip_summary = filtered_df.groupby('Source IP')['Count'].sum().reset_index().sort_values(by='Count', ascending=False).head(10)
        fig_ip = px.bar(ip_summary, x='Source IP', y='Count', title='Top 10 Sending IPs',
                        labels={'Count': 'Email Count', 'Source IP': 'IP Address'},
                        color='Count', color_continuous_scale='Viridis')
        st.plotly_chart(fig_ip, use_container_width=True)
        
        st.subheader("🛡️ Policy Disposition")
        disp_summary = filtered_df.groupby('Disposition')['Count'].sum().reset_index()
        fig_disp = px.pie(disp_summary, values='Count', names='Disposition', title='Disposition Breakdown',
                          color_discrete_sequence=px.colors.sequential.RdBu)
        st.plotly_chart(fig_disp, use_container_width=True)

    # Detailed breakdown
    st.subheader("🔍 Authentication Breakdown & Overrides")
    col_breakdown1, col_breakdown2 = st.columns(2)
    
    with col_breakdown1:
        st.markdown("**SPF & DKIM Results**")
        auth_summary = filtered_df.groupby(['SPF Eval', 'DKIM Eval'])['Count'].sum().reset_index()
        st.dataframe(auth_summary, use_container_width=True, hide_index=True)
        
    with col_breakdown2:
        st.markdown("**Override Reasons**")
        reason_summary = filtered_df.groupby('Override Reason')['Count'].sum().reset_index()
        st.dataframe(reason_summary, use_container_width=True, hide_index=True)

else:
    st.info("No DMARC reports loaded. Please upload files to begin.")
