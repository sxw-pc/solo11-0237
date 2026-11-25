"""Capture physical data copies reported by storage controllers."""
import hashlib
import json
from .store import one, event


def capture_page(db, page_id, copies):
    db.execute('CREATE TABLE IF NOT EXISTS storage_pages (id TEXT PRIMARY KEY,digest TEXT NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS storage_copies (page_id TEXT,line_no INTEGER,demand TEXT,dataset TEXT,node TEXT,byte_digest TEXT,at INTEGER,PRIMARY KEY(page_id,line_no))')
    if not isinstance(copies,list) or any(not isinstance(c,dict) or set(c)!={'demand','dataset','node','byte_digest','at'} for c in copies):
        return event(db,'storage_capture',page_id,'invalid_page',{})
    digest=hashlib.sha256(json.dumps(copies,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    old=one(db,'SELECT digest FROM storage_pages WHERE id=?',(page_id,))
    if old:return event(db,'storage_capture',page_id,'idempotent' if old['digest']==digest else 'conflict',{})
    for copy in copies:
        if not one(db,'SELECT id FROM demands WHERE id=?',(copy['demand'],)) or not one(db,'SELECT id FROM nodes WHERE id=?',(copy['node'],)):
            return event(db,'storage_capture',page_id,'unknown_location',{})
    db.execute('INSERT INTO storage_pages VALUES (?,?)',(page_id,digest))
    db.executemany('INSERT INTO storage_copies VALUES (?,?,?,?,?,?,?)',[(page_id,i,c['demand'],c['dataset'],c['node'],c['byte_digest'],c['at']) for i,c in enumerate(copies,1)])
    return event(db,'storage_capture',page_id,'captured',{'copies':len(copies)})
