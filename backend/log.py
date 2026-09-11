from playwright.sync_api import sync_playwright
def test_bulk_create_webhooks(playwright):
    api=playwright.request.new_context()
    res=api.post('https://api.qaautomationlabs.com/v1/webhooks/bulk',data={'links':[{'url':'https://hooks.example.com/abc','event':'order.created'},{'url':'https://hooks.example.com/abc'}]})
    print('Status:',res.status)
    print('Response:',res.text())