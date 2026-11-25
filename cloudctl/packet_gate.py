"""Provisional packet decision from ordered captured policy rows."""
from ipaddress import ip_address,ip_network

def decide(db,packet_id,src_ip,dst_port):
    db.execute('CREATE TABLE IF NOT EXISTS packet_decisions (packet_id TEXT PRIMARY KEY,action TEXT,rule_id TEXT)')
    try:rows=db.execute('SELECT rule_id,src_prefix,action FROM policy_rows WHERE dst_port=? ORDER BY priority,line_no',(dst_port,)).fetchall()
    except __import__('sqlite3').OperationalError:rows=[]
    row=next((r for r in rows if ip_address(src_ip) in ip_network(r[1])),None)
    action=row[2] if row else 'deny';rule=row[0] if row else ''
    with db:db.execute('INSERT INTO packet_decisions VALUES (?,?,?)',(packet_id,action,rule))
    return {'action':action,'rule_id':rule}
