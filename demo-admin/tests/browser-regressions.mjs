import assert from 'node:assert/strict';
const {chromium} = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const base = process.env.ADMIN_TEST_URL || 'http://127.0.0.1:5189';
const browser = await chromium.launch({headless:true});
const a1={id:'a1',name:'Codex laptop'}, a2={id:'a2',name:'Claude laptop'};
const caps=[{id:'c1',name:'Slack.Message.Read',action:'read',resourceId:'r1'},{id:'c2',name:'Slack.Message.Send',action:'write',resourceId:'r1'}];
const t1={tenantId:'t1',name:'Workspace Alpha',role:'ADMIN',breakGlass:false}, t2={tenantId:'t2',name:'Workspace Beta',role:'ADMIN',breakGlass:false};
const now=()=>new Date().toISOString();
const results=[];
async function fixture(overrides={}) {
  const page=await browser.newPage({viewport:{width:1440,height:900}});
  page.setDefaultTimeout(10000);
  const state={tenant:t1,signedIn:true,credentials:[],grants:[],writes:[],keyWrites:0,keyDelay:0,keyFailure:false,checkDelay:0,checkFailure:false,historyFailure:false,historyFailedOutcome:false,setupFailure:false,completed:true,failedSecond:false,alphaDelay:0,csrf:[],addedAgent:undefined,decisionSource:'AGENT_CALL',extraApp:false,...overrides};
  const errors=[];
  page.on('pageerror',error=>errors.push(error.message));
  await page.route(`${base}/api/**`,async route=>{
    const req=route.request(), url=new URL(req.url()), path=url.pathname, method=req.method();
    let data={},status=200;
    if(method==='POST') state.csrf.push(req.headers()['x-csrf-token']);
    if(path==='/api/auth/methods') data={oidc:true,developmentBootstrap:false};
    else if(path==='/api/session') { if(!state.signedIn)status=401;else data={userId:'u1',tenant:state.tenant,memberships:[t1,t2,{...t1,tenantId:'member',role:'MEMBER',name:'Member workspace'}],csrfToken:'csrf-'+(state.tenant?.tenantId||'picker')}; }
    else if(path==='/api/session/tenant') state.tenant=req.postDataJSON().tenantId==='t2'?t2:t1;
    else if(path==='/api/session/logout') state.signedIn=false;
    else if(!state.signedIn) status=401;
    else if(path==='/api/agents' && method==='POST') {state.addedAgent={id:'a3',name:req.postDataJSON().name};data=state.addedAgent;}
    else if(path==='/api/agents') { const alpha=state.tenant?.tenantId==='t1'; data={agents:alpha?[a1,a2,...(state.addedAgent?[state.addedAgent]:[])]:[{id:'b1',name:'Beta agent'}]}; if(alpha && state.alphaDelay)await new Promise(r=>setTimeout(r,state.alphaDelay)); }
    else if(path==='/api/resources') data={resources:[{id:'r1',name:'Slack workspace',type:'provider',provider:'slack'},...(state.extraApp?[{id:'r2',name:'Slack two',type:'provider',provider:'slack'}]:[])]};
    else if(path==='/api/capabilities') data={capabilities:caps};
    else if(path==='/api/tools') data={tools:[{name:'slack_search_messages',label:'Search Slack messages',resourceId:'r1',capabilityId:'c1',capabilityName:'Slack.Message.Read',trusted:true}]};
    else if(path==='/api/connections') data={connections:[{id:'conn1',resourceId:'r1',provider:'slack',status:'active'},...(state.extraApp?[{id:'conn2',resourceId:'r2',provider:'slack',status:'active'}]:[])]};
    else if(path==='/api/authorization/decisions') data={decisions:[{requestId:'request1',outcome:'allow',reason:'authorized',principalId:'a1',tool:'slack_search_messages',authorizationSource:state.decisionSource,decidedAt:now()}]};
    else if(path==='/api/authorization/check') { await new Promise(r=>setTimeout(r,state.checkDelay));if(state.checkFailure)status=503;else data={outcome:'allowed',message:'The delegated capability and owner policy allow this action.'}; }
    else if(path==='/api/executions/summary') {if(state.setupFailure)status=503;else data={hasCompletedExecution:state.completed};}
    else if(path==='/api/executions') data={executions:[{requestId:'older-completion',agentId:'a1',tool:'slack_search_messages',capability:'Slack.Message.Read',eventKind:'EXECUTION_COMPLETED',safeOutcome:'COMPLETED',authorizationSource:'AGENT_CALL',occurredAt:now()}]};
    else if(path.startsWith('/api/executions/')) {if(state.historyFailure)status=503;else data={events:state.historyFailedOutcome?[{requestId:'request1',agentId:'a1',tool:'slack_search_messages',capability:'Slack.Message.Read',eventKind:'PROVIDER_UNAVAILABLE',safeOutcome:'FAILED_PROVIDER_UNAVAILABLE',authorizationSource:'AGENT_CALL',occurredAt:now()}]:[]};}
    else if(path.includes('/credentials') && method==='POST') {state.keyWrites++; await new Promise(r=>setTimeout(r,state.keyDelay));if(state.keyFailure)status=503;else {state.credentials=[{credentialId:'key1',prefix:'fake-prefix',createdAt:now()}];data={...state.credentials[0],credential:'FAKE-ONE-TIME-KEY'};}}
    else if(path.includes('/credentials'))data={credentials:path.includes('/a1/')?state.credentials:[]};
    else if(path==='/api/delegations' && method==='POST') {const body=req.postDataJSON();state.writes.push(body.capabilityId);if(body.capabilityId==='c2'&&!state.failedSecond){state.failedSecond=true;status=403;}else{data={id:'g'+state.writes.length,granteeId:body.agentId,capabilityId:body.capabilityId,capabilityName:caps.find(c=>c.id===body.capabilityId).name,status:'active'};state.grants.push(data);}}
    else if(path==='/api/delegations')data={delegations:state.grants};
    try {await route.fulfill({status,contentType:'application/json',body:JSON.stringify(data)});}catch(error){if(!page.isClosed()&&!String(error).includes('Target closed'))throw error;}
  });
  return {page,state,errors};
}
async function run(name, fn){const f=await fixture();try{await fn(f);assert.deepEqual(f.errors,[]);results.push(name);console.log('PASS',name);}finally{await f.page.close();}}
async function agent(page,tab='access'){await page.goto(`${base}/admin/agents/a1${tab==='access'?'':`?tab=${tab}`}`);await page.getByRole('heading',{name:a1.name,exact:true}).waitFor();}
try {
  await run('OIDC-only sign-in and session reload',async({page,state})=>{
    state.signedIn=false;await page.goto(`${base}/admin`);await page.getByRole('link',{name:'Sign in with single sign-on'}).waitFor();assert.equal(await page.getByLabel('Local development bootstrap value').count(),0);
    state.signedIn=true;await page.reload();await page.getByRole('heading',{name:'Needs attention'}).waitFor();await page.reload();await page.getByRole('heading',{name:'Needs attention'}).waitFor();
    await page.getByRole('button',{name:'Sign out',exact:true}).click();await page.getByRole('link',{name:'Sign in with single sign-on'}).waitFor();assert.equal(state.csrf.at(-1),'csrf-t1');
  });
  await run('workspace switch discards cached data and late responses',async({page,state})=>{
    await page.goto(`${base}/admin/agents`);await page.getByRole('link',{name:a1.name,exact:true}).waitFor();state.alphaDelay=800;
    // Reload starts fresh A queries; switch before that response completes.
    await page.reload();await page.getByRole('button',{name:'Switch workspace'}).click();
    assert.equal(await page.getByRole('button',{name:'Member workspace · Member'}).isDisabled(),true);
    await page.getByRole('button',{name:'Workspace Beta · Administrator'}).click();await page.getByRole('link',{name:'Beta agent',exact:true}).waitFor();await page.waitForTimeout(1100);
    assert.equal(await page.getByRole('link',{name:a1.name,exact:true}).count(),0);assert.equal(await page.getByText('Workspace Alpha',{exact:true}).count(),0);
  });
  await run('expired session retires workspace state',async({page,state})=>{
    await page.goto(`${base}/admin`);await page.getByRole('heading',{name:'Needs attention'}).waitFor();state.signedIn=false;
    await page.goto(`${base}/admin/agents/a1?tab=setup`);await page.getByRole('link',{name:'Sign in with single sign-on'}).waitFor();assert.equal(await page.getByRole('heading',{name:a1.name,exact:true}).count(),0);
  });
  for(const rotate of [false,true])await run(`${rotate?'rotation':'enrollment'} protects pending one-time disclosure`,async({page,state})=>{
    if(rotate)state.credentials=[{credentialId:'old',prefix:'old-prefix',createdAt:now()}];state.keyDelay=800;await agent(page,'key');await page.getByRole('button',{name:rotate?'Replace key':'Create key',exact:true}).click();
    const dialog=page.getByRole('dialog');await dialog.getByRole('button',{name:rotate?'Replace key':'Create key',exact:true}).click();assert.equal(await dialog.getByRole('button',{name:'Cancel',exact:true}).isDisabled(),true);
    await page.keyboard.press('Escape');await page.mouse.click(1,1);await dialog.locator('form').evaluate(form=>{form.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}));});
    await page.getByText('FAKE-ONE-TIME-KEY',{exact:true}).waitFor();assert.equal(state.keyWrites,1);assert.equal(await page.getByRole('button',{name:'I’ve saved it'}).count(),1);await page.getByRole('button',{name:'I’ve saved it'}).click();
  });
  await run('key failure restores dismissal',async({page,state})=>{
    state.keyFailure=true;await agent(page,'key');await page.getByRole('button',{name:'Create key',exact:true}).click();await page.getByRole('dialog').getByRole('button',{name:'Create key',exact:true}).click();await page.getByRole('alert').waitFor();await page.getByRole('button',{name:'Cancel',exact:true}).click();assert.equal(await page.getByRole('dialog').count(),0);
  });
  await run('partial access retries only unfinished grants',async({page,state})=>{
    await agent(page);await page.getByRole('button',{name:'Give access',exact:true}).click();await page.getByRole('checkbox').nth(0).check();await page.getByRole('checkbox').nth(1).check();await page.getByRole('dialog').getByRole('button',{name:'Give access',exact:true}).click();await page.getByRole('alert').filter({hasText:'not permitted'}).waitFor();await page.getByRole('dialog').getByRole('button',{name:'Give access',exact:true}).click();await page.getByRole('dialog').waitFor({state:'hidden'});assert.deepEqual(state.writes,['c1','c2','c2']);assert.deepEqual(state.grants.map(g=>g.capabilityId),['c1','c2']);
  });
  await run('add-agent partial access retries only unfinished grants',async({page,state})=>{
    await page.goto(`${base}/admin/agents?new=1`);await page.getByLabel('Name',{exact:true}).fill('New agent');await page.getByRole('dialog').getByRole('button',{name:'Continue',exact:true}).click();await page.getByRole('heading',{name:'What can New agent do?'}).waitFor();await page.getByRole('checkbox').nth(0).check();await page.getByRole('checkbox').nth(1).check();await page.getByRole('button',{name:'Give access and continue',exact:true}).click();await page.getByRole('alert').filter({hasText:'not permitted'}).waitFor();await page.getByRole('button',{name:'Give access and continue',exact:true}).click();await page.getByRole('dialog').waitFor({state:'hidden'});assert.deepEqual(state.writes,['c1','c2','c2']);assert.deepEqual(state.grants.map(g=>g.capabilityId),['c1','c2']);
  });
  await run('app history navigation retires disconnect confirmation',async({page,state})=>{
    state.extraApp=true;await page.goto(`${base}/admin/apps/r2`);await page.getByRole('heading',{name:'Slack two',exact:true}).waitFor();await page.getByRole('combobox',{name:'Search the workspace'}).fill('Slack workspace');await page.getByRole('option').first().click();await page.getByRole('button',{name:'Disconnect',exact:true}).click();await page.getByRole('dialog').waitFor();await page.goBack();await page.getByRole('heading',{name:'Slack two',exact:true}).waitFor();assert.equal(await page.getByRole('dialog').count(),0);await page.goForward();await page.getByRole('heading',{name:'Slack workspace',exact:true}).waitFor();assert.equal(await page.getByRole('dialog').count(),0);
  });
  await run('successful empty history preserves decision-only feedback and unknown requests',async({page})=>{
    await page.goto(`${base}/admin/activity?request=request1`);await page.getByRole('dialog').getByText('Allowed',{exact:true}).first().waitFor();assert.equal(await page.getByRole('dialog').getByText('Execution history unavailable',{exact:true}).count(),0);await page.goto(`${base}/admin/activity?request=missing`);await page.getByRole('dialog').getByRole('heading',{name:'Request not found',exact:true}).waitFor();
  });
  await run('human previews stay identified as tests without execution evidence',async({page,state})=>{
    state.decisionSource='HUMAN_PREVIEW';await page.goto(`${base}/admin/activity?request=request1`);await page.getByRole('dialog').getByText('Allowed',{exact:true}).first().waitFor();assert.match(await page.getByRole('dialog').innerText(),/Access test/);
  });
  await run('preview snapshots inputs and clears a failed rerun',async({page,state})=>{
    await agent(page);await page.getByRole('button',{name:'Test access',exact:true}).click();state.checkDelay=400;await page.getByRole('button',{name:'Run test',exact:true}).click();assert.equal(await page.getByLabel('Tool',{exact:true}).isDisabled(),true);await page.getByRole('dialog').getByRole('heading',{name:'Read Slack messages'}).waitFor();state.checkFailure=true;await page.getByRole('button',{name:'Run test',exact:true}).click();await page.getByRole('alert').waitFor();assert.equal(await page.getByRole('dialog').locator('.result').count(),0);
  });
  await run('agent history navigation retires dialogs and pending previews',async({page,state})=>{
    await page.goto(`${base}/admin/agents/a2`);await page.getByRole('heading',{name:a2.name,exact:true}).waitFor();await page.getByRole('combobox',{name:'Search the workspace'}).fill('Codex');await page.getByRole('option').first().click();await page.getByRole('button',{name:'Test access',exact:true}).click();state.checkDelay=600;await page.getByRole('button',{name:'Run test',exact:true}).click();await page.goBack();await page.getByRole('heading',{name:a2.name,exact:true}).waitFor();await page.waitForTimeout(800);assert.equal(await page.getByRole('dialog').count(),0);
  });
  await run('history outage is primary feedback and retry reveals provider failure',async({page,state})=>{
    state.historyFailure=true;await page.goto(`${base}/admin/activity?request=request1`);const dialog=page.getByRole('dialog');await dialog.getByText('Execution history unavailable',{exact:true}).waitFor();assert.equal(await dialog.locator('.pill-ok').count(),0);state.historyFailure=false;state.historyFailedOutcome=true;await dialog.getByRole('button',{name:'Retry',exact:true}).click();await dialog.getByText('Failed',{exact:true}).waitFor();
  });
  await run('setup outage has retry and restores durable prior completion',async({page,state})=>{
    state.setupFailure=true;await agent(page,'setup');await page.getByText('Execution history is unavailable. Setup status could not be refreshed.').waitFor();state.setupFailure=false;await page.getByRole('button',{name:'Retry',exact:true}).click();await page.getByText('A completed call has been recorded for this agent.',{exact:false}).waitFor();
  });
  await run('global search navigates the active keyboard option',async({page})=>{
    await page.goto(`${base}/admin`);await page.getByRole('heading',{name:'Needs attention'}).waitFor();await page.keyboard.press('Control+k');const input=page.getByRole('combobox',{name:'Search the workspace'});await input.fill('laptop');await page.keyboard.press('ArrowDown');assert.equal(await page.getByRole('option',{selected:true}).getByText(a2.name,{exact:true}).count(),1);await page.keyboard.press('Enter');await page.getByRole('heading',{name:a2.name,exact:true}).waitFor();await input.fill('laptop');await page.keyboard.press('ArrowUp');await page.keyboard.press('Escape');assert.equal(await input.getAttribute('aria-expanded'),'false');
  });
  await run('desktop light, dark, and mobile layouts render without overflow',async({page})=>{
    await page.goto(`${base}/admin`);await page.getByRole('heading',{name:'Needs attention'}).waitFor();await page.screenshot({path:'/tmp/admin-ui-fixed-light.png'});await page.emulateMedia({colorScheme:'dark'});await page.screenshot({path:'/tmp/admin-ui-fixed-dark.png'});await page.setViewportSize({width:390,height:844});assert.equal(await page.getByRole('button',{name:'Switch workspace'}).isVisible(),true);assert.equal(await page.getByRole('button',{name:'Sign out',exact:true}).isVisible(),true);await page.screenshot({path:'/tmp/admin-ui-fixed-mobile.png'});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>window.innerWidth),false);
  });
  console.log(`${results.length} browser regressions passed`);
}finally{await browser.close();}
