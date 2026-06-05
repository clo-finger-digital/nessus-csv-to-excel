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
    Parses an OWASP ZAP HTML report. Extracts alert rows, maps numerical matrices,
    and isolates HTTP status lines/response headers into the output schema.
    """
    soup = BeautifulSoup(file_bytes, 'html.parser')
    zap_rows = []
    
    # ZAP HTML formats specific alert blocks under distinct alert-type list items
    alert_containers = soup.find_all(['li', 'div'], id=lambda x: x and x.startswith('alert-type-'))
    
    for container in alert_containers:
        # Extract the main Alert title header text
        title_header = container.find(['h4', 'h3'])
        if not title_header:
            continue
        alert_title = title_header.get_text().strip()
        
        # Locate the core metadata property table inside this alert context
        meta_table = container.find('table', class_='alert-types-table')
        if not meta_table:
            continue
            
        row_template = {
            "Source_Type": "ZAP", "Risk": "", "Confidence_Str": "", 
            "Host": "", "Protocol": "tcp", "Port": "0", 
            "Name": alert_title, "Synopsis": "", "Solution": "", 
            "See Also": "", "Output": ""
        }
        
        th_elements = meta_table.find_all('th', scope='row')
        for th in th_elements:
            label = th.get_text().strip().lower()
            td = th.find_next('td')
            if not td:
                continue
                
            if 'risk' in label:
                row_template["Risk"] = td.get_text().split('(')[0].strip()
            elif 'confidence' in label:
                row_template["Confidence_Str"] = td.get_text().split('(')[0].strip()
            elif 'description' in label:
                row_template["Synopsis"] = td.get_text().strip()
            elif 'solution' in label:
                row_template["Solution"] = td.get_text().strip()
            elif 'reference' in label:
                links = [a['href'] for a in td.find_all('a', href=True)]
                row_template["See Also"] = "\n".join(links)
                
        # Parse instances containing individual instances, targets, URLs, and Responses
        instances_table = container.find_next('table', class_='alert-instances-table')
        if instances_table:
            # Gather all individual asset/request headers from instances columns
            headers_th = [th.get_text().strip().lower() for th in instances_table.find_all('th')]
            url_idx, resp_idx = -1, -1
            
            for i, h_text in enumerate(headers_th):
                if 'url' in h_text or 'method' in h_text:
                    url_idx = i
                elif 'response' in h_text or 'header' in h_text:
                    resp_idx = i
                    
            rows_tr = instances_table.find_all('tr')[1:] # Skip column header mapping row
            for tr in rows_tr:
                tds = tr.find_all('td')
                if not tds:
                    continue
                    
                instance_row = row_template.copy()
                
                # Extract asset identifiers from active request path URLs
                if url_idx != -1 and url_idx < len(tds):
                    url_raw = tds[url_idx].get_text().strip()
                    instance_row["Host"] = url_raw
                    
                    # Deduce port mappings from standard string patterns
                    if 'https://' in url_raw:
                        instance_row["Port"] = "443"
                    elif 'http://' in url_raw:
                        instance_row["Port"] = "80"
                    port_match = re.search(r':(\d+)', url_raw.replace('http://','').replace('https://',''))
                    if port_match:
                        instance_row["Port"] = port_match.group(1)
                        
                # Extract HTTP status configuration text parameters from the response column
                if resp_idx != -1 and resp_idx < len(tds):
                    instance_row["Output"] = tds[resp_idx].get_text().strip()
                    
                if instance_row["Host"] and instance_row["Risk"]:
                    zap_rows.append(instance_row)
        else:
            # Fallback handling if no instances subgrid table is formatted for the alert
            site_span = soup.find('span', class_=['site', 'site-name'])
            if site_span:
                fallback_url = site_span.get_text().strip()
                row_template["Host"] = f"GET {fallback_url}"
                if '443' in fallback_url or 'https' in fallback_url:
                    row_template["Port"] = "443"
            if row_template["Host"] and row_template["Risk"]:
                zap_rows.append(row_template)
                
    return pd.DataFrame(zap_rows)

# --- Streamlit Shell Configurations ---
st.set_page_config(page_title="Vulnerability Follow-up Plan Hub", layout="wide")
st.title("Consolidated Security Scan Follow-up Plan Generator")
st.write("Merge Nessus CSV files and ZAP HTML reports seamlessly. Computes standard risk ratings and preserves target output layouts.")

if "master_dataset" not in st.session_state:
    st.session_state["master_dataset"] = pd.DataFrame(columns=["Source_Type", "Risk", "Host", "Protocol", "Port", "Name", "Synopsis", "Solution", "See Also", "Confidence_Str", "Output"])
if "logged_filenames" not in st.session_state:
    st.session_state["logged_filenames"] = set()

st.sidebar.header("App Settings")
project_name = st.sidebar.text_input("Project Name / Identifier", value="DH")
try:
    systems_tier = int(st.sidebar.number_input("Systems Tier (Integer Value)", min_value=1, max_value=10, value=2, step=1))
except ValueError:
    systems_tier = 1

if st.sidebar.button("Reset & Clear Upload Memory"):
    st.session_state["master_dataset"] = pd.DataFrame(columns=["Source_Type", "Risk", "Host", "Protocol", "Port", "Name", "Synopsis", "Solution", "See Also", "Confidence_Str", "Output"])
    st.session_state["logged_filenames"] = set()
    st.rerun()

uploaded_files = st.file_uploader("Upload raw scan data logs (Nessus CSV or ZAP HTML profiles)", type=["csv", "html"], accept_multiple_files=True)

if uploaded_files:
    new_data_loaded = False
    
    for uploaded_file in uploaded_files:
        if uploaded_file.name not in st.session_state["logged_filenames"]:
            try:
                file_bytes = uploaded_file.read()
                if uploaded_file.name.lower().endswith('.html'):
                    temp_df = parse_zap_html(file_bytes)
                else:
                    temp_df = pd.read_csv(io.BytesIO(file_bytes), dtype={"Host": str, "Port": str})
                    temp_df["Source_Type"] = "Nessus"
                    if "Output" not in temp_df.columns:
                        temp_df["Output"] = ""
                        
                headers = ["Source_Type", "Risk", "Host", "Protocol", "Port", "Name", "Synopsis", "Solution", "See Also", "Confidence_Str", "Output"]
                for h in headers:
                    if h not in temp_df.columns:
                        temp_df[h] = ""
                        
                temp_df = temp_df[headers]
                st.session_state["master_dataset"] = pd.concat([st.session_state["master_dataset"], temp_df], ignore_index=True)
                st.session_state["logged_filenames"].add(uploaded_file.name)
                new_data_loaded = True
            except Exception as e:
                st.error(f"Error parsing file configuration for '{uploaded_file.name}': {e}")
                
    if new_data_loaded:
        st.rerun()

if not st.session_state["logged_filenames"]:
    st.info("Awaiting input context. Please drop file reports into the entry target block above.")
else:
    st.sidebar.success(f"Staged Files ({len(st.session_state['logged_filenames'])}):")
    for name in sorted(st.session_state["logged_filenames"]):
        st.sidebar.caption(f"• {name}")
        
    master_df = st.session_state["master_dataset"].copy()
    
    # Clean string buffers cleanly
    for field_col in ["See Also", "Synopsis", "Solution", "Output", "Name", "Host"]:
        master_df[field_col] = master_df[field_col].fillna("").astype(str).str.strip()
        
    # Isolate valid rows and clear structural certificates alerts or ICMP timestamps
    master_df = master_df.dropna(subset=["Risk", "Host", "Name"])
    master_df = master_df[~master_df["Name"].str.contains(r"certificate", case=False, na=False)]
    master_df = master_df[~master_df["Name"].str.contains(r"icmp.*timestamp", case=False, na=False)]
    
    master_df["Risk_Cleaned"] = master_df["Risk"].astype(str).str.strip()
    master_df = master_df[~master_df["Risk_Cleaned"].str.lower().isin(["none", "informational", "0", "nan", ""])]
    
    if master_df.empty:
        st.warning("No actionable security items remain after applying cleanup exclusions.")
    else:
        # Split tracking dataframes to prevent Nessus version parsing logic from crossing into ZAP strings
        nessus_subset = master_df[master_df["Source_Type"] == "Nessus"].copy()
        zap_subset = master_df[master_df["Source_Type"] == "ZAP"].copy()
        
        processed_tracks = []
        
        # --- Stage 1: Process Nessus Elements ---
        if not nessus_subset.empty:
            nessus_subset["Family"], nessus_subset["Ver_Tuple"] = zip(*nessus_subset["Name"].apply(get_vulnerability_family_and_version))
            nessus_subset = nessus_subset.sort_values(by=["Host", "Protocol", "Port", "Family", "Ver_Tuple"], ascending=[True, True, True, True, False])
            deduped_nessus = nessus_subset.drop_duplicates(subset=["Host", "Protocol", "Port", "Family"], keep="first")
            
            grouped_nessus = deduped_nessus.groupby(["Protocol", "Port", "Name"], dropna=False)
            for (protocol, port, name), group in grouped_nessus:
                first_row = group.iloc[0]
                unique_hosts = sorted(group["Host"].unique())
                hosts_str = "\n".join(unique_hosts)
                
                r_lower = str(first_row["Risk_Cleaned"]).lower()
                impact = 3 if 'critical' in r_lower or 'high' in r_lower else (2 if 'medium' in r_lower else 1)
                likelihood = 2 if impact >= 2 else 1
                
                processed_tracks.append({
                    "Source": "Nessus", "System/Asset ID": hosts_str, "Protocol": protocol, "Port": port,
                    "Security Domain Area": "Operation Security", "Risk Name/Observation": name,
                    "Vulnerability\n/Threat": first_row["Synopsis"], "Action plan": first_row["Solution"],
                    "Impact": impact, "Likelihood": likelihood, "Output": first_row["Output"], "Reference": first_row["See Also"]
                })
                
        # --- Stage 2: Process ZAP HTML Elements ---
        if not zap_subset.empty:
            # Group ZAP logs strictly by unique matching Protocol, Port, and precise Risk Alert Name
            grouped_zap = zap_subset.groupby(["Protocol", "Port", "Name"], dropna=False)
            for (protocol, port, name), group in grouped_zap:
                first_row = group.iloc[0]
                
                # Consolidate request paths URLs vertically onto separate lines
                unique_urls = sorted(group["Host"].unique())
                urls_str = "\n".join(unique_urls)
                
                # Consolidate raw HTTP status strings or headers vertically onto separate lines
                unique_outputs = [out for out in group["Output"].unique() if out]
                outputs_str = "\n".join(unique_outputs)
                
                r_lower = str(first_row["Risk_Cleaned"]).lower()
                conf_str = str(first_row["Confidence_Str"]).lower()
                
                # Map integers based on configuration criteria rules
                impact = 3 if 'high' in r_lower or 'critical' in r_lower else (2 if 'medium' in r_lower else 1)
                likelihood = 3 if 'high' in conf_str or 'confirmed' in conf_str else (2 if 'medium' in conf_str else 1)
                
                processed_tracks.append({
                    "Source": "ZAP", "System/Asset ID": urls_str, "Protocol": protocol, "Port": port,
                    "Security Domain Area": "Operation Security", "Risk Name/Observation": name,
                    "Vulnerability\n/Threat": first_row["Synopsis"], "Action plan": first_row["Solution"],
                    "Impact": impact, "Likelihood": likelihood, "Output": outputs_str, "Reference": first_row["See Also"]
                })
                
        # Calculate Risk Score products across the full joined array list
        for r in processed_tracks:
            r["Risk Rating"] = r["Impact"] * r["Likelihood"] * systems_tier
            r["Risk Rating/ Level"] = "Low" if r["Risk Rating"] <= 9 else ("Medium" if r["Risk Rating"] <= 18 else "High")
            
        # Separate systems components to group Nessus outputs on top, followed by ZAP lines
        nessus_final = [r for r in processed_tracks if r["Source"] == "Nessus"]
        zap_final = [r for r in processed_tracks if r["Source"] == "ZAP"]
        
        # Sort internal categories descending by score
        nessus_final.sort(key=lambda x: x["Risk Rating"], reverse=True)
        zap_final.sort(key=lambda x: x["Risk Rating"], reverse=True)
        
        # Assemble Worksheet Spreadsheet Object Architecture
        excel_buffer = io.BytesIO()
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "Follow-up Plan"
        
        ws.merge_cells("D1:H1")
        title_cell = ws["D1"]
        title_cell.value = "Follow-up Plan"
        title_cell.alignment = Alignment(horizontal="left", vertical="center")
        
        headers_blueprint = [
            'Observe /Findings#', 'System/Asset ID', 'Protocol', 'Port', 
            'Risk Treatment method (Acceptance / Reduction / Avoidance / Transfer)', 
            'Security Domain Area', 'Risk Name/Observation', 'Vulnerability\n/Threat', 
            'Action plan', 'Risk Rating/ Level', 'Impact', 'Likelihood', 
            'Systems Tier', 'Risk Rating', 'Target completion date\n(dd/mm/yyyy)', 
            'Status', 'Details of follow-up actions', 'Acutal Completion date\n(dd/mm/yyyy)', 
            'Reference', 'Output'
        ]
        
        for c_idx, title_text in enumerate(headers_blueprint, start=3):
            ws.cell(row=3, column=c_idx, value=title_text)
            
        total_rows_count = len(nessus_final) + len(zap_final)
        ws.auto_filter.ref = f"C3:V{total_rows_count + 3}"
        
        current_write_row = 4
        
        # Hydrate Nessus records sequentially (v1, v2, v3...)
        for i, r_data in enumerate(nessus_final):
            ws.cell(row=current_write_row, column=3, value=f"v{i + 1}")
            ws.cell(row=current_write_row, column=4, value=r_data["System/Asset ID"])
            ws.cell(row=current_write_row, column=5, value=r_data["Protocol"])
            ws.cell(row=current_write_row, column=6, value=r_data["Port"])
            ws.cell(row=current_write_row, column=8, value=r_data["Security Domain Area"])
            ws.cell(row=current_write_row, column=9, value=r_data["Risk Name/Observation"])
            ws.cell(row=current_write_row, column=10, value=r_data["Vulnerability\n/Threat"])
            ws.cell(row=current_write_row, column=11, value=r_data["Action plan"])
            ws.cell(row=current_write_row, column=12, value=r_data["Risk Rating/ Level"])
            ws.cell(row=current_write_row, column=13, value=r_data["Impact"])
            ws.cell(row=current_write_row, column=14, value=r_data["Likelihood"])
            ws.cell(row=current_write_row, column=15, value=systems_tier)
            ws.cell(row=current_write_row, column=16, value=r_data["Risk Rating"])
            ws.cell(row=current_write_row, column=21, value=r_data["Reference"])
            ws.cell(row=current_write_row, column=22, value=r_data["Output"])
            current_write_row += 1
            
        # Append ZAP logs sequentially directly beneath (A1, A2, A3...)
        for i, r_data in enumerate(zap_final):
            ws.cell(row=current_write_row, column=3, value=f"A{i + 1}")
            ws.cell(row=current_write_row, column=4, value=r_data["System/Asset ID"])
            ws.cell(row=current_write_row, column=5, value=r_data["Protocol"])
            ws.cell(row=current_write_row, column=6, value=r_data["Port"])
            ws.cell(row=current_write_row, column=8, value=r_data["Security Domain Area"])
            ws.cell(row=current_write_row, column=9, value=r_data["Risk Name/Observation"])
            ws.cell(row=current_write_row, column=10, value=r_data["Vulnerability\n/Threat"])
            ws.cell(row=current_write_row, column=11, value=r_data["Action plan"])
            ws.cell(row=current_write_row, column=12, value=r_data["Risk Rating/ Level"])
            ws.cell(row=current_write_row, column=13, value=r_data["Impact"])
            ws.cell(row=current_write_row, column=14, value=r_data["Likelihood"])
            ws.cell(row=current_write_row, column=15, value=systems_tier)
            ws.cell(row=current_write_row, column=16, value=r_data["Risk Rating"])
            ws.cell(row=current_write_row, column=21, value=r_data["Reference"])
            ws.cell(row=current_write_row, column=22, value=r_data["Output"])
            current_write_row += 1
            
        center_align = Alignment(horizontal="center", vertical="top", wrap_text=True)
        left_align = Alignment(horizontal="left", vertical="top", wrap_text=True)
        
        for row in ws.iter_rows(min_row=3, max_row=total_rows_count + 3, min_col=3, max_col=22):
            for cell in row:
                if cell.column in [3, 5, 6, 8, 12, 13, 14, 15, 16]:
                    cell.alignment = center_align
                else:
                    cell.alignment = left_align
                    
        column_widths = {
            'C': 18, 'D': 25, 'E': 10, 'F': 10, 'G': 15, 'H': 18, 'I': 35, 'J': 45, 'K': 50, 
            'L': 18, 'M': 10, 'N': 10, 'O': 12, 'P': 12, 'Q': 15, 'R': 12, 'S': 20, 'T': 15, 'U': 30, 'V': 45
        }
        for col_letter, width in column_widths.items():
            ws.column_dimensions[col_letter].width = width
            
        wb.save(excel_buffer)
        
        st.write("---")
        st.download_button(
            label="Download Structured Excel Follow-up Plan",
            data=excel_buffer.getvalue(),
            file_name=f"Follow up Plan - {project_name}.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
