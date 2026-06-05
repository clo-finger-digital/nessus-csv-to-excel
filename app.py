import streamlit as st
import pandas as pd
import openpyxl
import io
import re
from bs4 import BeautifulSoup
from openpyxl.utils import get_column_letter
from openpyxl.styles import Alignment

def parse_version_string(v_str):
    match = re.match(r'^(\d+(?:\.\d+)*)([a-z]*)$', str(v_str).strip(), re.IGNORECASE)
    if match:
        nums_str, letters = match.groups()
        nums = tuple(int(x) for x in nums_str.split('.'))
        letters = letters.lower()
        return (nums, len(letters), letters)
    return ((), 0, '')

def get_vulnerability_family_and_version(name_str):
    name_str = str(name_str).strip()
    if '<' in name_str:
        family = name_str.split('<')[0].strip()
    elif '<=' in name_str:
        family = name_str.split('<=')[0].strip()
    else:
        tokens = re.findall(r'\b\d+(?:\.\d+)+[a-z]*\b', name_str, re.IGNORECASE)
        family = name_str
        for t in tokens:
            family = family.replace(t, "[VERSION]")
            
    all_tokens = re.findall(r'\b\d+(?:\.\d+)+[a-z]*\b', name_str, re.IGNORECASE)
    if all_tokens:
        max_token = max(all_tokens, key=parse_version_string)
        max_version = parse_version_string(max_token)
    else:
        max_version = ((), 0, '')
        
    return family, max_version

def parse_zap_html(file_bytes):
    """
    Hierarchical parser optimized for Checkmarx/OWASP ZAP HTML report architectures.
    Decodes strings directly and references native list IDs to avoid parsing anomalies.
    Applies direct filtering to discard Low or Informational risks immediately.
    """
    html_text = file_bytes.decode('utf-8', errors='ignore')
    soup = BeautifulSoup(html_text, 'html.parser')
    zap_rows = []
    
    # Locate all structural category headings with integrated metrics
    risk_groups = soup.find_all('li', id=lambda x: x and 'risk-' in x and 'confidence-' in x)
    
    for r_group in risk_groups:
        id_str = r_group.get('id', '')
        match = re.search(r'risk-(\d)-confidence-(\d)', id_str)
        if not match:
            continue
            
        risk_num = int(match.group(1))
        conf_num = int(match.group(2))
        
        # --- SKIP CONDITION 1: Prevent low/informational rows from parsing ---
        if risk_num <= 1:
            continue
            
        risk_map = {3: "High", 2: "Medium"}
        conf_map = {3: "High", 2: "Medium", 1: "Low"}
        
        risk_val = risk_map.get(risk_num, "Medium")
        conf_val = conf_map.get(conf_num, "Low")
        
        h5_elements = r_group.find_all('h5')
        for h5 in h5_elements:
            alert_title = h5.get_text().strip()
            alert_title = re.sub(r'\s*\(\d+\)\s*$', '', alert_title) # Strip instance counters like ' (1)'
            
            parent_li = h5.find_parent('li')
            if not parent_li:
                continue
                
            tables = parent_li.find_all('table', class_='alerts-table')
            for table in tables:
                row_data = {
                    "Source_Type": "ZAP", "Risk": risk_val, "Confidence_Str": conf_val,
                    "Host": "GET https://localhost", "Protocol": "Nil", "Port": "Nil",
                    "Name": alert_title, "Synopsis": "", "Solution": "", "See Also": "", "Output": ""
                }
                
                details_container = table.find_parent('details')
                if details_container:
                    summary_elem = details_container.find('summary')
                    if summary_elem:
                        url_span = summary_elem.find('span', class_='request-method-n-url')
                        if url_span:
                            row_data["Host"] = url_span.get_text().strip()
                        else:
                            row_data["Host"] = summary_elem.get_text().strip()
                            
                tr_elements = table.find_all('tr')
                for tr in tr_elements:
                    th = tr.find('th')
                    td = tr.find('td')
                    if not th or not td:
                        continue
                        
                    label = th.get_text().strip().lower()
                    
                    if 'description' in label:
                        row_data["Synopsis"] = td.get_text().strip()
                    elif 'solution' in label:
                        row_data["Solution"] = td.get_text().strip()
                    elif 'reference' in label:
                        links = [a['href'] for a in td.find_all('a', href=True)]
                        row_data["See Also"] = "\n".join(links)
                    elif 'response' in label:
                        pre_tag = td.find('pre')
                        if pre_tag:
                            row_data["Output"] = pre_tag.get_text().strip()
                        else:
                            row_data["Output"] = td.get_text().strip()
                            
                if row_data["Host"] and row_data["Risk"]:
                    zap_rows.append(row_data)
                    
    return pd.DataFrame(zap_rows)

# --- Streamlit Shell Configurations ---
st.set_page_config(page_title="Vulnerability Follow-up Plan Hub", layout="wide")
st.title("Consolidated Security Scan Follow-up Plan Generator")
st.write("Upload your files into their respective categories below. The tool compiles data seamlessly into the target layout.")

if "nessus_dataset" not in st.session_state:
    st.session_state["nessus_dataset"] = pd.DataFrame(columns=["Source_Type", "Risk", "Host", "Protocol", "Port", "Name", "Synopsis", "Solution", "See Also", "Confidence_Str", "Output"])
if "zap_dataset" not in st.session_state:
    st.session_state["zap_dataset"] = pd.DataFrame(columns=["Source_Type", "Risk", "Host", "Protocol", "Port", "Name", "Synopsis", "Solution", "See Also", "Confidence_Str", "Output"])
if "logged_nessus_files" not in st.session_state:
    st.session_state["logged_nessus_files"] = set()
if "logged_zap_files" not in st.session_state:
    st.session_state["logged_zap_files"] = set()

st.sidebar.header("App Settings")
project_name = st.sidebar.text_input("Project Name / Identifier", value="DH")
try:
    systems_tier = int(st.sidebar.number_input("Systems Tier (Integer Value)", min_value=1, max_value=10, value=2, step=1))
except ValueError:
    systems_tier = 1

if st.sidebar.button("Reset & Clear Upload Memory"):
    st.session_state["nessus_dataset"] = pd.DataFrame(columns=["Source_Type", "Risk", "Host", "Protocol", "Port", "Name", "Synopsis", "Solution", "See Also", "Confidence_Str", "Output"])
    st.session_state["zap_dataset"] = pd.DataFrame(columns=["Source_Type", "Risk", "Host", "Protocol", "Port", "Name", "Synopsis", "Solution", "See Also", "Confidence_Str", "Output"])
    st.session_state["logged_nessus_files"] = set()
    st.session_state["logged_zap_files"] = set()
    st.rerun()

col1, col2 = st.columns(2)

with col1:
    st.subheader("Nessus Scanning Data")
    uploaded_nessus = st.file_uploader("Upload raw Nessus CSV files", type=["csv"], accept_multiple_files=True, key="nessus_input")
    if uploaded_nessus:
        new_nessus = False
        for f in uploaded_nessus:
            if f.name not in st.session_state["logged_nessus_files"]:
                try:
                    temp_df = pd.read_csv(f, dtype={"Host": str, "Port": str})
                    temp_df["Source_Type"] = "Nessus"
                    headers = ["Source_Type", "Risk", "Host", "Protocol", "Port", "Name", "Synopsis", "Solution", "See Also", "Confidence_Str", "Output"]
                    for h in headers:
                        if h not in temp_df.columns:
                            temp_df[h] = ""
                    st.session_state["nessus_dataset"] = pd.concat([st.session_state["nessus_dataset"], temp_df[headers]], ignore_index=True)
                    st.session_state["logged_nessus_files"].add(f.name)
                    new_nessus = True
                except Exception as e:
                    st.error(f"Error parsing Nessus file '{f.name}': {e}")
        if new_nessus:
            st.rerun()

with col2:
    st.subheader("OWASP ZAP Data (Medium & High Only)")
    uploaded_zap = st.file_uploader("Upload OWASP ZAP HTML reports", type=["html"], accept_multiple_files=True, key="zap_input")
    if uploaded_zap:
        new_zap = False
        for f in uploaded_zap:
            if f.name not in st.session_state["logged_zap_files"]:
                try:
                    file_bytes = f.read()
                    temp_df = parse_zap_html(file_bytes)
                    headers = ["Source_Type", "Risk", "Host", "Protocol", "Port", "Name", "Synopsis", "Solution", "See Also", "Confidence_Str", "Output"]
                    for h in headers:
                        if h not in temp_df.columns:
                            temp_df[h] = ""
                    st.session_state["zap_dataset"] = pd.concat([st.session_state["zap_dataset"], temp_df[headers]], ignore_index=True)
                    st.session_state["logged_zap_files"].add(f.name)
                    new_zap = True
                except Exception as e:
                    st.error(f"Error parsing ZAP report '{f.name}': {e}")
        if new_zap:
            st.rerun()

has_nessus = len(st.session_state["logged_nessus_files"]) > 0
has_zap = len(st.session_state["logged_zap_files"]) > 0

if not has_nessus and not has_zap:
    st.info("Awaiting file context inputs. Please populate target fields above.")
else:
    st.sidebar.markdown("---")
    st.sidebar.markdown("**Loaded Inventories:**")
    if has_nessus:
        st.sidebar.caption(f"Nessus CSVs ({len(st.session_state['logged_nessus_files'])} files)")
    if has_zap:
        st.sidebar.caption(f"ZAP HTMLs ({len(st.session_state['logged_zap_files'])} files)")

    nessus_df = st.session_state["nessus_dataset"].copy()
    zap_
