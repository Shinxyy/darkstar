# api.py
import os
import xml.etree.ElementTree as ET
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel

from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp

# ---- Pydantic models ----

class TargetCreate(BaseModel):
    name: str
    hosts: List[str]
    port_range: Optional[str] = "1-65535"
    port_list_id: Optional[str] = None

class TargetInfo(BaseModel):
    id: str
    name: str
    hosts: List[str]

class TaskCreate(BaseModel):
    name: str
    target_id: str
    # Optional: specify scan config & scanner; 
    # if omitted, defaults will be used
    config_id: Optional[str] = None
    scanner_id: Optional[str] = None

class TaskInfo(BaseModel):
    id: str
    name: str
    status: str

# ---- FastAPI app ----

app = FastAPI(title="OpenVAS GMP HTTP API")

SOCK_PATH = os.getenv("GMP_SOCKET", "/run/gvmd/gvmd.sock")
GVM_USER = os.getenv("GVM_USER", "admin")
GVM_PASS = os.getenv("GVM_PASSWORD", "admin")

def get_gmp():
    """Dependency: yields an authenticated GMP session."""
    conn = UnixSocketConnection(path=SOCK_PATH)
    with Gmp(conn) as gmp:
        gmp.authenticate(GVM_USER, GVM_PASS)
        yield gmp

# ---- Helpers to parse GMP XML ----

def _parse_xml(resp) -> ET.Element:
    if isinstance(resp, bytes):
        resp = resp.decode()
    return ET.fromstring(resp)

# ---- Endpoints ----


@app.post("/targets", response_model=TargetInfo)
def create_target(body: TargetCreate, gmp: Gmp = Depends(get_gmp)):
    """Create a new scan target."""
    resp = gmp.create_target(
        name=body.name,
        hosts=body.hosts,
        port_range=body.port_range,
        port_list_id=body.port_list_id
    )
    print(f"create_target response: {resp}")
    root = _parse_xml(resp)
    status = root.get("status", "unknown status")
    id = root.get("id", "")
    status_text = root.get("status_text", "unknown error")

    if status == "201":
        return TargetInfo(
            id=id,
            name=body.name,
            hosts=body.hosts,
        )
    else:
        raise HTTPException(int(status), f"{status_text}")
        

@app.get("/targets", response_model=List[TargetInfo])
def list_targets(gmp: Gmp = Depends(get_gmp)):
    """List all scan targets."""
    resp = gmp.get_targets()
    root = _parse_xml(resp)
    out = []
    for tgt in root.findall(".//target"):
        hosts = [h.text for h in tgt.findall("hosts/ip")]
        out.append(TargetInfo(id=tgt.get("id"), name=tgt.findtext("name"), hosts=hosts))
    return out

@app.post("/tasks", response_model=TaskInfo)
def create_task(body: TaskCreate, gmp: Gmp = Depends(get_gmp)):
    """Create a scan task (but not start it yet)."""
    # pick defaults if not provided:
    if body.config_id is None:
        cfg_resp = gmp.get_scan_configs()
        cfg_root = _parse_xml(cfg_resp)
        # find config named “Full and fast”
        cfg = cfg_root.find(".//config[name='Full and fast']") or cfg_root.find(".//config")
        body.config_id = cfg.get("id")
    if body.scanner_id is None:
        scn_resp = gmp.get_scanners()
        scn_root = _parse_xml(scn_resp)
        scn = scn_root.find(".//scanner")
        body.scanner_id = scn.get("id")

    resp = gmp.create_task(
        name=body.name,
        config_id=body.config_id,
        target_id=body.target_id,
        scanner_id=body.scanner_id
    )
    root = _parse_xml(resp)
    status = root.get("status", "unknown error")
    id_     = root.get("id", "")
    status_text = root.get("status_text", "unknown error")

    if status == "201":
        return TaskInfo(
            id=id_,
            name=body.name,
            status="Created"     # or pull status_text if you prefer
        )

    raise HTTPException(int(status), status_text)


@app.post("/tasks/{task_id}/start")
def start_task(task_id: str, gmp: Gmp = Depends(get_gmp)):
    """Start a previously created scan task."""
    resp = gmp.start_task(task_id)
    root = _parse_xml(resp)
    # return the raw GMP response attributes
    return {elem.tag: elem.attrib for elem in root}

@app.get("/tasks", response_model=List[TaskInfo])
def list_tasks(gmp: Gmp = Depends(get_gmp)):
    """List all scan tasks and their status."""
    resp = gmp.get_tasks()
    root = _parse_xml(resp)
    out = []
    for t in root.findall(".//task"):
        out.append(TaskInfo(
            id=t.get("id"),
            name=t.findtext("name"),
            status=t.findtext("status")
        ))
    return out

@app.get("/tasks/{task_id}/status", response_model=TaskInfo)
def get_task_status(task_id: str, gmp: Gmp = Depends(get_gmp)):
    """Get status of a specific task."""
    resp = gmp.get_task(task_id=task_id)
    root = _parse_xml(resp)
    t = root.find(".//task")
    return TaskInfo(id=task_id, name=t.findtext("name"), status=t.findtext("status"))

@app.get("/reports/{report_id}")
def get_report(report_id: str, gmp: Gmp = Depends(get_gmp)):
    """Fetch a finished report (defaulting to XML format)."""
    # pick the XML report format
    rf = _parse_xml(gmp.get_report_formats()).find(".//report_format[name='XML']") 
    rf_id = rf.get("id") if rf is not None else _parse_xml(gmp.get_report_formats()).find(".//report_format").get("id")

    report = gmp.get_report(report_id=report_id, report_format_id=rf_id)
    if isinstance(report, bytes):
        report = report.decode()
    return Response(content=report, media_type="application/xml")