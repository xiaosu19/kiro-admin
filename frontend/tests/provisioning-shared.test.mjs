import test from 'node:test';
import assert from 'node:assert/strict';
import { renderToStaticMarkup } from 'react-dom/server';
import { loadSource } from './load-source.mjs';
import { mountHook } from './hooks.mjs';

const logic = await loadSource('provisioningLogic');
const ui = await loadSource('Provisioning');
const accounts = Array.from({ length: 20 }, (_, index) => ({ id: index + 1, account_number: `a${index + 1}`,
  name: `AWS ${index + 1}`, aws_account_id: String(123456789000 + index), active: true, proxy_status: 'enabled' }));
const plans = [{ id: 1, name: 'Pro', active: true }, { id: 2, name: 'Power', active: true }];
const group = { id: 'group-a1', owner_id: 7, aws_account_id: 1, name: 'Existing team', state: 'ready', remote_id: 'aws-group-a1',
  revision: 8, policy: { mode: 'days', days: 9, revision: 3 } };
const shared = () => ({ quantity: 4, plan_id: 1, policy: { mode: 'days', days: 30 }, exports: { csv: true, txt: true, json: false } });
function selected(settings = shared()) {
  return accounts.reduce((rows, account) => logic.toggleProvisioningAccount(rows, account, settings), []);
}
function find(node, predicate) {
  if (!node || typeof node !== 'object') return null;
  if (Array.isArray(node)) { for (const child of node) { const found = find(child, predicate); if (found) return found; } return null; }
  return predicate(node) ? node : find(node.props?.children, predicate);
}
const byTest = (host, id) => find(host.current, node => node.props?.['data-testid'] === id);

test('twenty selected accounts inherit current shared settings without sharing mutable values', () => {
  assert.equal(typeof logic.defaultProvisioningSettings, 'function');
  assert.equal(typeof logic.toggleProvisioningAccount, 'function');
  const defaults = shared(), rows = selected(defaults);
  assert.equal(rows.length, 20);
  assert.ok(rows.every(row => row.settingsMode === 'shared' && row.quantity === 4 && row.plan_id === 1 && row.policy.days === 30));
  defaults.policy.days = 99; defaults.exports.json = true;
  rows[0].policy.days = 7; rows[0].exports.csv = false;
  assert.equal(rows[1].policy.days, 30); assert.equal(rows[1].exports.csv, true); assert.equal(rows[1].exports.json, false);
  const changed = { ...shared(), quantity: 8, plan_id: 2, policy: { mode: 'at', stop_at: '2026-11-01T02:00:00Z' }, exports: { csv: false, txt: true, json: true } };
  const updated = logic.applySharedProvisioningSettings(rows, changed);
  assert.ok(updated.every(row => row.quantity === 8 && row.plan_id === 2 && row.policy.stop_at === changed.policy.stop_at && row.exports.json));
  assert.equal(rows[1].quantity, 4, 'editing shared settings does not mutate the previous draft');
});

test('per-account overrides survive shared edits and returning to shared keeps the chosen group', () => {
  const rows = selected();
  rows[0] = { ...logic.withGroup(rows[0], group), settingsMode: 'custom', quantity: 2, plan_id: 2,
    policyMode: 'change', policy: { mode: 'days', days: 5 }, overwrite_individual: true, exports: { csv: false, txt: false, json: true } };
  const changed = { ...shared(), quantity: 10, policy: { mode: 'none' }, exports: { csv: true, txt: false, json: false } };
  const updated = logic.applySharedProvisioningSettings(rows, changed);
  assert.deepEqual(updated[0], rows[0]); assert.equal(updated[1].quantity, 10);
  const restored = logic.inheritProvisioningSettings(updated[0], changed);
  assert.equal(restored.settingsMode, 'shared'); assert.equal(restored.quantity, 10); assert.equal(restored.plan_id, 1);
  assert.equal(restored.groupId, group.id); assert.equal(restored.groupRevision, 8); assert.equal(restored.policyRevision, 3);
  assert.equal(restored.policyMode, 'inherit'); assert.equal(restored.overwrite_individual, false);
  const body = logic.provisioningBody([restored], accounts, [group], 7);
  assert.equal('stop_policy' in body.accounts[0], false); assert.equal('overwrite_individual' in body.accounts[0], false);
});

test('shared edits preserve existing-group inheritance and revision checks while new groups receive the shared stop policy', () => {
  const rows = selected(); rows[0] = logic.withGroup(rows[0], group);
  const updated = logic.applySharedProvisioningSettings(rows, { ...shared(), quantity: 6, policy: { mode: 'days', days: 45 } });
  const body = logic.provisioningBody(updated, accounts, [group], 7);
  assert.equal(body.accounts[0].quantity, 6); assert.equal('stop_policy' in body.accounts[0], false);
  assert.deepEqual(body.accounts[0].group, { mode: 'existing', group_id: group.id, expected_revision: 8, expected_policy_revision: 3 });
  assert.deepEqual(body.accounts[1].stop_policy, { mode: 'days', days: 45 });
  assert.throws(() => logic.provisioningBody(updated, accounts, [{ ...group, revision: 9 }], 7), /分组或规则已变化/);
  const changedGroup = { ...group, revision: 9, policy: { mode: 'none', revision: 4 } };
  const refreshed = logic.withGroup(updated[0], changedGroup);
  assert.equal(refreshed.settingsMode, 'shared'); assert.equal(refreshed.quantity, 6); assert.equal(refreshed.policyMode, 'inherit');
  assert.equal('stop_policy' in logic.provisioningBody([refreshed], accounts, [changedGroup], 7).accounts[0], false);
});

test('new selections and reselected accounts use the latest common settings and saved admission intent stays immutable', () => {
  const rows = selected();
  const intent = logic.provisioningIntent(logic.provisioningBody(rows, accounts, [], 7), 'c'.repeat(64));
  const changed = { ...shared(), quantity: 9, plan_id: 2, exports: { csv: true, txt: false, json: true } };
  let next = logic.applySharedProvisioningSettings(rows, changed);
  next = logic.toggleProvisioningAccount(next, accounts[0], changed);
  assert.equal(next.length, 19);
  next = logic.toggleProvisioningAccount(next, accounts[0], changed);
  assert.equal(next.length, 20); assert.equal(next.at(-1).quantity, 9); assert.equal(next.at(-1).exports.json, true);
  assert.equal(intent.accounts[0].quantity, 4); assert.equal(intent.accounts[0].exports.json, false);
  assert.ok(Object.isFrozen(intent.accounts[0].stop_policy));
});

function configurationHost(initialDisabled = false) {
  let current;
  const host = mountHook(disabled => {
    assert.equal(typeof ui.useProvisioningConfiguration, 'function');
    const configuration = ui.useProvisioningConfiguration(1); current = configuration;
    return ui.ProvisioningConfigurations({ shared: configuration.shared, rows: configuration.drafts, accounts, plans, groups: [group], actorId: 7,
      disabled, onSharedChange: configuration.changeShared, onChange: configuration.changeDraft, onRemove: configuration.remove });
  }, initialDisabled);
  return { host, get configuration() { return current; } };
}
function seed(environment) {
  environment.configuration.changeShared(shared()); environment.host.render();
  for (const account of accounts) environment.configuration.toggle(account);
  environment.host.render();
}

test('twenty accounts render one shared form and compact summaries until an individual override is opened', () => {
  assert.equal(typeof ui.ProvisioningConfigurations, 'function');
  const environment = configurationHost(); seed(environment);
  const { host } = environment;
  let html = renderToStaticMarkup(host.current);
  assert.equal((html.match(/aria-label="公共 新增人数"/g) || []).length, 1);
  assert.equal((html.match(/data-testid="provisioning-summary-\d+"/g) || []).length, 20);
  assert.equal((html.match(/class="panel provisioning-account-fields"/g) || []).length, 0);
  assert.equal((html.match(/aria-label="a\d+ 分组"/g) || []).length, 20);
  byTest(host, 'provisioning-customize-1').props.onClick(); host.render();
  html = renderToStaticMarkup(host.current);
  assert.equal((html.match(/class="panel provisioning-account-fields"/g) || []).length, 1);
  assert.match(html, /aria-label="a1 新增人数"/); assert.doesNotMatch(html, /aria-label="a2 新增人数"/);
  assert.equal(environment.configuration.drafts[0].settingsMode, 'custom');
  byTest(host, 'provisioning-customize-1').props.onClick(); host.render();
  assert.equal(find(host.current, node => node.type === ui.ProvisioningAccountFields), null, 'collapsing preserves the override');
  assert.equal(environment.configuration.drafts[0].settingsMode, 'custom'); host.unmount();
});

test('real configuration controls propagate common edits, keep custom settings and explicitly restore inheritance', () => {
  const environment = configurationHost(); seed(environment); const { host } = environment;
  byTest(host, 'provisioning-customize-1').props.onClick(); host.render();
  let editor = find(host.current, node => node.type === ui.ProvisioningAccountFields);
  const fields = ui.ProvisioningAccountFields(editor.props);
  find(fields, node => node.props?.['aria-label'] === 'a1 新增人数').props.onChange({ target: { value: '2' } }); host.render();
  const common = find(host.current, node => node.type === ui.ProvisioningSharedFields);
  const commonFields = ui.ProvisioningSharedFields(common.props);
  find(commonFields, node => node.props?.['aria-label'] === '公共 新增人数').props.onChange({ target: { value: '12' } }); host.render();
  assert.equal(environment.configuration.shared.quantity, 12); assert.equal(environment.configuration.drafts[0].quantity, 2);
  assert.ok(environment.configuration.drafts.slice(1).every(row => row.quantity === 12));
  byTest(host, 'provisioning-restore-1').props.onClick(); host.render();
  assert.equal(environment.configuration.drafts[0].quantity, 12); assert.equal(environment.configuration.drafts[0].settingsMode, 'shared');
  assert.equal(find(host.current, node => node.type === ui.ProvisioningAccountFields), null);
  byTest(host, 'provisioning-remove-20').props.onClick(); host.render();
  assert.equal(environment.configuration.drafts.length, 19);
  environment.configuration.toggle(accounts[19]); host.render();
  assert.equal(environment.configuration.drafts.at(-1).quantity, 12); host.unmount();
});

test('pending admission locks shared edits, group choices, override controls and account removal', () => {
  const environment = configurationHost(); seed(environment); const { host } = environment;
  byTest(host, 'provisioning-customize-1').props.onClick(); host.render();
  const before = JSON.stringify(environment.configuration.drafts), beforeShared = JSON.stringify(environment.configuration.shared);
  host.render(true);
  const html = renderToStaticMarkup(host.current);
  assert.match(html, /aria-label="公共设置" disabled=""|disabled="" aria-label="公共设置"/);
  const common = find(host.current, node => node.type === ui.ProvisioningSharedFields);
  common.props.onChange({ ...shared(), quantity: 99 });
  const editor = find(host.current, node => node.type === ui.ProvisioningAccountFields);
  assert.equal(editor.props.disabled, true); editor.props.onChange({ ...editor.props.row, quantity: 99 });
  const groupControl = find(host.current, node => node.type === ui.ProvisioningGroupSelect && node.props.account.id === 1);
  assert.equal(groupControl.props.disabled, true); groupControl.props.onChange(logic.withGroup(environment.configuration.drafts[0], group));
  for (const id of ['provisioning-customize-2', 'provisioning-restore-1', 'provisioning-remove-1']) {
    const button = byTest(host, id); assert.equal(button.props.disabled, true); button.props.onClick();
  }
  host.render();
  assert.equal(JSON.stringify(environment.configuration.drafts), before); assert.equal(JSON.stringify(environment.configuration.shared), beforeShared);
  host.unmount();
});

test('five AWS accounts with quantity 100 mean 100 each and show 500 total', () => {
  const environment = configurationHost();
  environment.configuration.changeShared({ ...shared(), quantity: 100 }); environment.host.render();
  for (const account of accounts.slice(0, 5)) environment.configuration.toggle(account);
  environment.host.render();
  assert.deepEqual(environment.configuration.drafts.map(row => row.quantity), [100, 100, 100, 100, 100]);
  const html = renderToStaticMarkup(environment.host.current);
  assert.match(html, /每个账号新增人数/); assert.match(html, /共新增 500 人/);
  environment.host.unmount();
});
