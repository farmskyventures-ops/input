import json
import sys
from urllib import request, error
from http.cookiejar import CookieJar
from pathlib import Path

BASE = sys.argv[1].rstrip('/')
OUT = Path(sys.argv[2])

class Session:
    def __init__(self):
        self.cj = CookieJar()
        self.opener = request.build_opener(request.HTTPCookieProcessor(self.cj))

    def call(self, method, path, data=None):
        body = None
        headers = {'Accept': 'application/json'}
        if data is not None:
            body = json.dumps(data).encode('utf-8')
            headers['Content-Type'] = 'application/json'
        req = request.Request(BASE + path, data=body, headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=30) as resp:
                raw = resp.read().decode('utf-8')
                try:
                    payload = json.loads(raw) if raw else {}
                except Exception:
                    payload = {'raw': raw}
                return resp.status, payload
        except error.HTTPError as e:
            raw = e.read().decode('utf-8')
            try:
                payload = json.loads(raw) if raw else {}
            except Exception:
                payload = {'raw': raw}
            return e.code, payload

results = []

def check(name, ok, detail=''):
    results.append((name, ok, detail))
    if not ok:
        print(f'FAIL: {name} :: {detail}')

admin = Session()
status, data = admin.call('GET', '/api/auth/status')
check('auth status endpoint', status == 200, str((status, data)))

status, data = admin.call('POST', '/api/login', {'phone': '+2547500000', 'password': '1224'})
check('admin login', status == 200 and data.get('user', {}).get('role') in ('admin', 'super_admin'), str((status, data)))

status, data = admin.call('GET', '/api/me')
check('session me', status == 200 and data.get('user', {}).get('full_name'), str((status, data)))

status, data = admin.call('GET', '/api/integrations/transunion/status')
check('transunion status', status == 200 and 'live' in data, str((status, data)))

# Create operations/finance user
ops_phone = '+254711111111'
status, data = admin.call('POST', '/api/users', {
    'full_name': 'Ops Finance Tester',
    'phone': ops_phone,
    'email': 'ops@example.com',
    'role': 'operations_finance',
    'label': 'Operations Desk',
    'region': 'Nakuru'
})
ops_created = status == 200 and data.get('id')
ops_password = data.get('password') if ops_created else None
ops_user_id = data.get('id') if ops_created else None
check('create operations_finance user', bool(ops_created), str((status, data)))

# Create PAYGO equipment
paygo_product = {
    'sku': 'EQ-PAYGO-001',
    'name': 'Solar Irrigation Pump PAYGO',
    'category': 'Equipment',
    'description': 'Solar pump with PAYGO terms for smallholder irrigation.',
    'unit': 'unit',
    'buying_price': 50000,
    'quantity': 5,
    'cash_markup_pct': 8,
    'credit_markup_pct': 15,
    'reorder_threshold': 1,
    'payment_option_mode': 'both',
    'cash_enabled': True,
    'financing_enabled': True,
    'financing_model': 'paygo',
    'financing_interest_pct': 12,
    'financing_frequency': 'weekly',
    'financing_term_min_months': 3,
    'financing_term_max_months': 6,
    'cash_deposit_pct': 10,
    'financing_deposit_pct': 15,
    'cash_terms_text': '10% deposit to confirm cash order, balance before dispatch.',
    'financing_terms_text': '15% deposit, then weekly PAYGO installments.',
    'cash_terms_doc_url': 'data:application/pdf;base64,SGVsbG8=',
    'financing_terms_doc_url': 'data:application/pdf;base64,SGVsbG8=',
    'transunion_product_code': 'TU-PAYGO-PUMP'
}
status, data = admin.call('POST', '/api/products', paygo_product)
paygo_id = data.get('id') if status == 200 else None
check('create PAYGO equipment', status == 200 and paygo_id, str((status, data)))

# Create normal financing equipment
loan_product = dict(paygo_product)
loan_product.update({
    'sku': 'EQ-LOAN-001',
    'name': 'Dairy Chaff Cutter Loan',
    'description': 'Interest-based financing example.',
    'financing_model': 'loan_interest',
    'financing_interest_pct': 18,
    'financing_frequency': 'monthly',
    'cash_deposit_pct': 100,
    'financing_deposit_pct': 20,
    'financing_terms_text': '20% deposit, then monthly payments over the selected term.',
    'transunion_product_code': 'TU-LOAN-CHAFF'
})
status, data = admin.call('POST', '/api/products', loan_product)
loan_id = data.get('id') if status == 200 else None
check('create standard financing equipment', status == 200 and loan_id, str((status, data)))

# Verify products carry new fields
status, data = admin.call('GET', '/api/products')
products = data.get('products', []) if status == 200 else []
paygo_product_row = next((p for p in products if p.get('id') == paygo_id), None)
loan_product_row = next((p for p in products if p.get('id') == loan_id), None)
check('product financing fields persisted', bool(paygo_product_row and paygo_product_row.get('financing_model') == 'paygo' and loan_product_row and loan_product_row.get('financing_model') == 'loan_interest'), str(paygo_product_row))

# Sign-up flow with ID uploads
customer = Session()
new_phone = '+254733123456'
status, data = customer.call('POST', '/api/signup/request-otp', {'phone': new_phone, 'full_name': 'Preview Farmer'})
otp = data.get('demo_otp')
check('signup request otp', status == 200 and otp, str((status, data)))

status, data = customer.call('POST', '/api/signup/verify', {
    'phone': new_phone,
    'full_name': 'Preview Farmer',
    'code': otp,
    'password': '4455',
    'national_id': '12345678',
    'id_front_url': 'data:image/png;base64,AAAA',
    'id_back_url': 'data:image/png;base64,BBBB'
})
check('signup verify with ID front/back', status == 200 and data.get('user', {}).get('role') == 'customer', str((status, data)))

status, data = customer.call('GET', '/api/me')
customer_user_id = data.get('user', {}).get('id') if status == 200 else None
check('customer auto login after signup', status == 200 and customer_user_id, str((status, data)))

status, data = customer.call('GET', '/api/customers')
customer_rows = data.get('customers', []) if status == 200 else []
my_customer = next((c for c in customer_rows if c.get('user_id') == customer_user_id), None)
customer_id = my_customer.get('id') if my_customer else None
check('customer profile created on signup', bool(customer_id and my_customer.get('id_front_url') and my_customer.get('id_back_url')), str(my_customer))

# PAYGO quote and KYC gating
status, data = customer.call('POST', '/api/murabaha/quote', {'product_id': paygo_id, 'quantity': 1, 'payment_type': 'financing', 'term_months': 4})
check('PAYGO quote', status == 200 and data.get('financing_model') == 'paygo' and data.get('deposit_pct') == 15, str((status, data)))

status, data = customer.call('POST', '/api/murabaha/apply', {'product_id': paygo_id, 'quantity': 1, 'payment_type': 'financing', 'term_months': 4, 'delivery_location': 'Nakuru', 'consent': True})
check('financing blocked before verification', status == 412 and data.get('error') == 'kyc_required', str((status, data)))

status, data = customer.call('POST', f'/api/customers/{customer_id}/verify', {})
check('customer verification / TransUnion stub', status == 200 and 'provider_reference' in data and 'credit_score' in data, str((status, data)))

status, data = customer.call('POST', '/api/murabaha/apply', {'product_id': paygo_id, 'quantity': 1, 'payment_type': 'financing', 'term_months': 4, 'delivery_location': 'Nakuru', 'consent': True})
contract_id = data.get('id') if status == 200 else None
check('PAYGO financing application after verification', status == 200 and contract_id and data.get('status') == 'pending', str((status, data)))

# Cash quote validates deposit behavior
status, data = customer.call('POST', '/api/murabaha/quote', {'product_id': paygo_id, 'quantity': 1, 'payment_type': 'cash', 'term_months': 0})
check('cash quote deposit policy', status == 200 and data.get('deposit_pct') == 10 and data.get('amount_due_now') > 0, str((status, data)))

# Approve as admin, dispatch as ops/finance
status, data = admin.call('POST', f'/api/murabaha/{contract_id}/decision', {'action': 'approve', 'notes': 'approved in smoke test'})
check('approve financing contract', status == 200 and data.get('ok') is True, str((status, data)))

ops = Session()
status, data = ops.call('POST', '/api/login', {'phone': ops_phone, 'password': ops_password})
check('operations_finance login', status == 200 and data.get('user', {}).get('role') == 'operations_finance', str((status, data)))

# ops user cannot edit inventory directly
status, data = ops.call('PUT', f'/api/products/{paygo_id}', {'name': 'Nope'})
check('operations_finance cannot edit products', status == 403, str((status, data)))

status, data = ops.call('POST', '/api/change-requests', {'entity_type': 'product', 'entity_id': paygo_id, 'requested_action': 'update pricing', 'reason': 'Need admin review'})
check('operations_finance can submit change request', status == 200 and data.get('ok') is True, str((status, data)))

status, data = ops.call('POST', f'/api/murabaha/{contract_id}/dispatch', {})
check('operations_finance can dispatch approved contract', status == 200 and data.get('ok') is True, str((status, data)))

status, data = admin.call('GET', f'/api/murabaha/{contract_id}')
contract = data.get('contract', {}) if status == 200 else {}
check('contract dispatch persisted', status == 200 and contract.get('dispatch_status') == 'dispatched', str((status, contract)))

status, data = admin.call('GET', '/api/users')
user_rows = data.get('users', []) if status == 200 else []
ops_row = next((u for u in user_rows if u.get('id') == ops_user_id), None)
check('user label and permissions persisted', bool(ops_row and ops_row.get('label') == 'Operations Desk' and ops_row.get('permissions', {}).get('dispatch') is True and not ops_row.get('permissions', {}).get('edit')), str(ops_row))

status, data = admin.call('GET', '/api/export/datasets')
check('export datasets available', status == 200 and len(data.get('datasets', [])) > 0, str((status, data)))

status, html = admin.call('GET', '/')
check('shell preview route', status == 200, str((status, html)))

# Super Admin permission catalog + custom role template
status, data = admin.call('GET', '/api/permissions')
check('permission catalog loads', status == 200 and isinstance(data.get('permissions'), list) and len(data['permissions']) >= 5, str((status, data)))

status, data = admin.call('POST', '/api/permissions', {'permission_key': 'smoke_test_perm', 'label': 'Smoke Permission', 'category': 'workflow', 'description': 'created by smoke test'})
check('super-admin add permission check-box', status == 200 and data.get('ok'), str((status, data)))

status, data = admin.call('POST', '/api/role-templates', {'role_key': 'smoke_role', 'label': 'Smoke Role', 'description': 'created by smoke test', 'permissions': {'view': True, 'smoke_test_perm': True}})
check('super-admin save role template', status == 200 and data.get('ok'), str((status, data)))

status, data = admin.call('GET', '/api/permissions')
found_perm = any(p.get('permission_key') == 'smoke_test_perm' for p in (data.get('permissions') or []))
found_role = any(r.get('role_key') == 'smoke_role' for r in (data.get('roles') or []))
check('catalog persists new permission + role', found_perm and found_role, str((found_perm, found_role)))

admin.call('DELETE', '/api/role-templates/smoke_role')
admin.call('DELETE', '/api/permissions/smoke_test_perm')

# Admin can edit, suspend, reactivate, and delete farmer profiles
status, data = admin.call('GET', '/api/customers')
farmers = [c for c in (data.get('customers') or []) if not c.get('user_id') or c.get('user_id') != customer_user_id]
target = farmers[0] if farmers else None
if target:
    farmer_id = target['id']
    status, data = admin.call('PUT', f'/api/customers/{farmer_id}', {'sacco_membership': 'yes', 'existing_loans': '15000'})
    check('admin can edit farmer profile', status == 200, str((status, data)))
    status, data = admin.call('PUT', f'/api/customers/{farmer_id}/status', {'status': 'suspended'})
    check('admin can suspend farmer profile', status == 200, str((status, data)))
    status, data = admin.call('PUT', f'/api/customers/{farmer_id}/status', {'status': 'active'})
    check('admin can reactivate farmer profile', status == 200, str((status, data)))
else:
    check('admin can edit farmer profile', False, 'no farmer available to edit')

passed = sum(1 for _, ok, _ in results if ok)
failed = sum(1 for _, ok, _ in results if not ok)
lines = ['# FarmSky Preview Smoke Test', '', f'- Base URL: {BASE}', f'- Passed: {passed}', f'- Failed: {failed}', '', '## Checks']
for name, ok, detail in results:
    marker = 'PASS' if ok else 'FAIL'
    lines.append(f'- **{marker}** {name}')
    if detail and not ok:
        lines.append(f'  - Detail: `{detail[:500]}`')
OUT.write_text('\n'.join(lines) + '\n')
print(json.dumps({'passed': passed, 'failed': failed, 'report': str(OUT)}))
if failed:
    sys.exit(1)
