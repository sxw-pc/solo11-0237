import sqlite3,unittest
from cloudctl.image_capture import import_page,record_file,record_signoff,record_revocation
from cloudctl.boot_release import issue
from cloudctl.machine_load import record_load,open_service,status,history

WV2,B1,WV3,B2,WV3R,B3,WV3X='d-wv2','d-b1','d-wv3','d-b2','d-wv3r','d-b3','d-wv3x'

def seed_evidence(db):
    """The demo site: verified worker-v2/base-1, a new worker-v3 page whose base-2
    key is revoked at minute 18, a rebuilt worker-v3r/base-3, and a page that only
    renames the top image while still depending on base-2."""
    for file_id,name,digest,at in [('file-wv2','worker-v2',WV2,10),('file-b1','base-1',B1,9),
            ('file-wv3','worker-v3',WV3,20),('file-b2','base-2',B2,19),
            ('file-wv3r','worker-v3r',WV3R,23),('file-b3','base-3',B3,22),('file-wv3x','worker-v3x',WV3X,23)]:
        record_file(db,file_id,name,digest,at)
    for signoff_id,digest,signer,at in [('sig-wv2',WV2,'trusted',10),('sig-b1',B1,'trusted',9),
            ('sig-wv3',WV3,'trusted',20),('sig-b2',B2,'key-b2',19),
            ('sig-wv3r',WV3R,'trusted',23),('sig-b3',B3,'trusted',22),('sig-wv3x',WV3X,'trusted',23)]:
        record_signoff(db,signoff_id,digest,signer,at)
    import_page(db,'pg-old',[
        {'image':'worker-v2','base':'base-1','digest':WV2,'signer':'trusted','abi':'v1','built_at':10},
        {'image':'base-1','base':'','digest':B1,'signer':'trusted','abi':'v1','built_at':9}],11)
    import_page(db,'pg-new',[
        {'image':'worker-v3','base':'base-2','digest':WV3,'signer':'trusted','abi':'v1','built_at':20},
        {'image':'base-2','base':'','digest':B2,'signer':'key-b2','abi':'v1','built_at':19}],20)
    import_page(db,'pg-rebuild',[
        {'image':'worker-v3r','base':'base-3','digest':WV3R,'signer':'trusted','abi':'v1','built_at':23},
        {'image':'base-3','base':'','digest':B3,'signer':'trusted','abi':'v1','built_at':22}],23)
    import_page(db,'pg-rename',[
        {'image':'worker-v3x','base':'base-2','digest':WV3X,'signer':'trusted','abi':'v1','built_at':23}],23)

def revoke_b2(db,received):
    return record_revocation(db,'rev-b2','key-b2',18,received)

class ImageLineageTests(unittest.TestCase):
    def setUp(self):self.db=sqlite3.connect(':memory:')

    def test_rollback_to_verified_old_version(self):
        db=self.db;seed_evidence(db);revoke_b2(db,20)
        blocked=issue(db,'p-v3','worker-v3',abi='v1',issued_at=20)
        self.assertEqual(blocked['decision'],'blocked')
        self.assertEqual(blocked['reason'],'revoked_signer')
        self.assertEqual(blocked['layer'],'base-2')
        permit=issue(db,'p-v2','worker-v2',abi='v1',issued_at=21)
        self.assertEqual(permit['decision'],'issued')
        self.assertEqual(permit['chain'],[WV2,B1])
        self.assertEqual(permit['digest'],WV2)
        self.assertEqual(record_load(db,'r-21','m1','p-v2',[WV2,B1],21)['decision'],'running')
        self.assertEqual(open_service(db,'o-21','m1',21)['decision'],'serving')
        m=status(db,'m1')
        self.assertEqual(m['status'],'serving');self.assertEqual(m['digest'],WV2);self.assertFalse(m['migration_owed'])
        # a signed permit alone is not a running version: without the minute-21 load receipt m2 never ran
        self.assertEqual(issue(db,'p-v2-m2','worker-v2',abi='v1',issued_at=21)['decision'],'issued')
        self.assertEqual(status(db,'m2')['status'],'unknown')
        self.assertEqual(open_service(db,'o-21-m2','m2',21)['decision'],'not_running')

    def test_full_rebuild_replaces_revoked_base(self):
        db=self.db;seed_evidence(db);revoke_b2(db,20)
        self.assertEqual(issue(db,'p-v3','worker-v3',abi='v1')['decision'],'blocked')
        # renaming only the top image still carries revoked base-2 and cannot pass as a rebuild
        renamed=issue(db,'p-v3x','worker-v3x',abi='v1',issued_at=23)
        self.assertEqual(renamed['decision'],'blocked');self.assertEqual(renamed['reason'],'revoked_signer')
        permit=issue(db,'p-v3r','worker-v3r',abi='v1',issued_at=23)
        self.assertEqual(permit['decision'],'issued')
        self.assertEqual(permit['chain'],[WV3R,B3])
        self.assertEqual(record_load(db,'r-24','m1','p-v3r',[WV3R,B3],24)['decision'],'running')
        self.assertEqual(open_service(db,'o-24','m1',24)['decision'],'serving')
        self.assertEqual(status(db,'m1')['digest'],WV3R)
        # the interface name cannot stand in for bytes: abi and digest-chain mismatches are refused
        self.assertEqual(issue(db,'p-abi','worker-v3r',abi='v2')['reason'],'abi_mismatch')
        bad=record_load(db,'r-bad','m2','p-v3r',[WV3R,B2],24)
        self.assertEqual(bad['decision'],'chain_mismatch')
        self.assertEqual(status(db,'m2')['status'],'quarantined')

    def test_late_revocation_quarantines_booted_machine(self):
        db=self.db;seed_evidence(db)
        permit=issue(db,'p-v3','worker-v3',abi='v1',issued_at=20)
        self.assertEqual(permit['decision'],'issued')
        self.assertEqual(record_load(db,'r-21','m1','p-v3',[WV3,B2],21)['decision'],'running')
        self.assertEqual(open_service(db,'o-21','m1',21)['decision'],'serving')
        notice=revoke_b2(db,23)
        self.assertEqual(notice['status'],'recorded')
        self.assertEqual(notice['quarantined'],['m1'])
        m=status(db,'m1')
        self.assertEqual(m['status'],'quarantined');self.assertTrue(m['migration_owed'])
        # the machine cannot run the workload until it re-proves a qualified image
        self.assertEqual(open_service(db,'o-22','m1',22)['decision'],'not_running')
        # a late load of the revoked chain is quarantined as well
        self.assertEqual(record_load(db,'r-25','m9','p-v3',[WV3,B2],25)['decision'],'quarantined')
        # the original permit, the boot facts and the captured pages are not deleted
        self.assertEqual(db.execute('SELECT digest FROM boot_permits WHERE id=?',('p-v3',)).fetchone()[0],WV3)
        self.assertEqual(db.execute('SELECT decision FROM load_receipts WHERE id=?',('r-21',)).fetchone()[0],'running')
        self.assertEqual(db.execute('SELECT COUNT(*) FROM image_rows WHERE page_id=?',('pg-new',)).fetchone()[0],2)
        # re-prove with the verified old image, then restore the v1 service
        rollback=issue(db,'p-v2','worker-v2',abi='v1',issued_at=24)
        self.assertEqual(record_load(db,'r-24','m1','p-v2',rollback['chain'],24)['decision'],'running')
        self.assertEqual(open_service(db,'o-24','m1',24)['decision'],'serving')
        m=status(db,'m1')
        self.assertEqual(m['status'],'serving');self.assertEqual(m['digest'],WV2);self.assertFalse(m['migration_owed'])
        kinds=[e['kind'] for e in history(db,'m1')]
        self.assertIn('quarantined',kinds);self.assertIn('recovered',kinds)
        # replaying the notice returns the original result and does not re-quarantine the recovered machine
        replay=revoke_b2(db,23)
        self.assertEqual(replay['status'],'replayed');self.assertEqual(replay['quarantined'],['m1'])
        self.assertEqual(status(db,'m1')['status'],'serving')

    def test_missing_layer_blocks_permit(self):
        db=self.db
        record_file(db,'file-wx','worker-x','d-wx',10)
        record_signoff(db,'sig-wx','d-wx','trusted',10)
        import_page(db,'pg-gap',[{'image':'worker-x','base':'base-9','digest':'d-wx','signer':'trusted','abi':'v1','built_at':10}],11)
        blocked=issue(db,'p-gap','worker-x',abi='v1')
        self.assertEqual(blocked['decision'],'blocked')
        self.assertEqual(blocked['reason'],'missing_layer')
        self.assertEqual(blocked['layer'],'base-9')
        self.assertEqual(db.execute('SELECT COUNT(*) FROM boot_permits').fetchone()[0],0)

    def test_same_name_different_digest_blocks_permit(self):
        db=self.db
        for file_id,name,digest,at in [('f-b2a','base-2','d-b2a',9),('f-b2b','base-2','d-b2b',9),
                ('f-wy','worker-y','d-wy',10),('f-wz1','worker-z','d-wz1',8),('f-wz2','worker-z','d-wz2',8)]:
            record_file(db,file_id,name,digest,at)
        for signoff_id,digest,at in [('s-b2a','d-b2a',9),('s-b2b','d-b2b',9),('s-wy','d-wy',10),('s-wz1','d-wz1',8),('s-wz2','d-wz2',8)]:
            record_signoff(db,signoff_id,digest,'trusted',at)
        import_page(db,'pg-a',[
            {'image':'worker-y','base':'base-2','digest':'d-wy','signer':'trusted','abi':'v1','built_at':10},
            {'image':'base-2','base':'','digest':'d-b2a','signer':'trusted','abi':'v1','built_at':9}],10)
        import_page(db,'pg-b',[{'image':'base-2','base':'','digest':'d-b2b','signer':'trusted','abi':'v1','built_at':9}],11)
        blocked=issue(db,'p-y','worker-y',abi='v1')
        self.assertEqual(blocked['decision'],'blocked')
        self.assertEqual(blocked['reason'],'ambiguous_layer');self.assertEqual(blocked['layer'],'base-2')
        import_page(db,'pg-c',[{'image':'worker-z','base':'','digest':'d-wz1','signer':'trusted','abi':'v1','built_at':8}],10)
        import_page(db,'pg-d',[{'image':'worker-z','base':'','digest':'d-wz2','signer':'trusted','abi':'v1','built_at':8}],11)
        self.assertEqual(issue(db,'p-z','worker-z',abi='v1')['reason'],'ambiguous_image')
        # the late pages did not overwrite the earlier rows
        self.assertEqual(db.execute('SELECT COUNT(*) FROM image_rows WHERE image=?',('base-2',)).fetchone()[0],2)
        self.assertEqual(db.execute('SELECT COUNT(*) FROM image_rows WHERE image=?',('worker-z',)).fetchone()[0],2)
        # a new page reusing the same image name and build time cannot replace the filed bytes either
        import_page(db,'pg-old',[{'image':'worker-v2','base':'','digest':WV2,'signer':'trusted','abi':'v1','built_at':10}],10)
        import_page(db,'pg-e',[{'image':'worker-v2','base':'','digest':'d-wv2-alt','signer':'trusted','abi':'v1','built_at':10}],12)
        self.assertEqual(issue(db,'p-v2','worker-v2',abi='v1')['reason'],'ambiguous_image')

    def test_cycle_blocks_permit(self):
        db=self.db
        record_file(db,'f-a','img-a','d-a',10);record_file(db,'f-b','img-b','d-b',9)
        record_signoff(db,'s-a','d-a','trusted',10);record_signoff(db,'s-b','d-b','trusted',9)
        import_page(db,'pg-loop',[
            {'image':'img-a','base':'img-b','digest':'d-a','signer':'trusted','abi':'v1','built_at':10},
            {'image':'img-b','base':'img-a','digest':'d-b','signer':'trusted','abi':'v1','built_at':9}],11)
        self.assertEqual(issue(db,'p-loop','img-a',abi='v1')['reason'],'cycle')

    def test_steps_recover_by_commit_id(self):
        db=self.db;seed_evidence(db);revoke_b2(db,20)
        first=issue(db,'p-v2','worker-v2',abi='v1',issued_at=21)
        retry=issue(db,'p-v2','worker-v2',abi='v1',issued_at=21)
        self.assertEqual(retry['decision'],'issued')
        self.assertEqual(retry['chain'],first['chain']);self.assertEqual(retry['digest'],first['digest'])
        with self.assertRaises(ValueError):issue(db,'p-v2','worker-v3',abi='v1')
        self.assertEqual(db.execute('SELECT COUNT(*) FROM boot_permits').fetchone()[0],1)
        self.assertEqual(record_load(db,'r-21','m1','p-v2',[WV2,B1],21)['decision'],'running')
        replay=record_load(db,'r-21','m1','p-v2',[WV2,B1],21)
        self.assertEqual(replay['decision'],'running');self.assertTrue(replay['replayed'])
        with self.assertRaises(ValueError):record_load(db,'r-21','m1','p-v2',[WV2],21)
        self.assertEqual(db.execute('SELECT COUNT(*) FROM load_receipts').fetchone()[0],1)
        self.assertEqual(open_service(db,'o-21','m1',21)['decision'],'serving')
        self.assertEqual(open_service(db,'o-21','m1',21)['decision'],'serving')
        self.assertEqual(db.execute('SELECT COUNT(*) FROM service_opens').fetchone()[0],1)
        self.assertEqual(record_file(db,'file-wv2','worker-v2',WV2,10)['status'],'replayed')
        with self.assertRaises(ValueError):record_file(db,'file-wv2','worker-v2','d-other',10)
        self.assertEqual(record_signoff(db,'sig-wv2',WV2,'trusted',10)['status'],'replayed')
        with self.assertRaises(ValueError):record_signoff(db,'sig-wv2',WV2,'trusted',11)
        self.assertEqual(record_revocation(db,'rev-b2','key-b2',18,20)['status'],'replayed')
        with self.assertRaises(ValueError):record_revocation(db,'rev-b2','key-b2',17,20)
        # a blocked attempt commits nothing and may be retried once the evidence arrives
        self.assertEqual(issue(db,'p-v3','worker-v3',abi='v1')['decision'],'blocked')
        self.assertEqual(db.execute("SELECT COUNT(*) FROM boot_permits WHERE id='p-v3'").fetchone()[0],0)

if __name__=='__main__':unittest.main()
