// ServerAgentLink i18n：轻量词典切换，语言偏好存 localStorage。
// 模板里所有面向用户的静态文案用 data-i18n="key" 标记，切换时整页替换文本。

var SAL_I18N = {
  en: {
    // 通用
    brand_sub: 'Server Console',
    logout: 'Sign out',
    login: 'Sign in',
    login_sub: 'ServerAgentLink · Server Console',
    username: 'Username',
    password: 'Password',
    login_failed: 'Invalid username or password',
    back: '← Back to servers',
    // 服务器页
    servers: 'Servers',
    servers_sub: 'Manage target servers, their coding accounts and per-directory permissions',
    add_server: 'Add Server',
    name: 'Name',
    host: 'Host',
    ssh_port: 'SSH Port',
    root_user: 'Root User',
    root_password: 'Root Password',
    server_list: 'Servers',
    status: 'Status',
    accounts: 'Accounts',
    actions: 'Actions',
    enter: 'Open',
    test_conn: 'Test Connection',
    delete: 'Delete',
    confirm_del_server: 'Delete this server and remotely remove all its accounts?',
    verified: 'Verified',
    unverified: 'Unverified',
    exposed_accounts: 'Accounts exposed to agents',
    exposed_sub: 'SSH credentials of these accounts are served to agents via MCP; toggle per account on the server detail page.',
    server: 'Server',
    dir_perms: 'Directories',
    no_servers: 'No servers yet. Add your first target server above.',
    no_exposed: 'No accounts exposed to agents. Open a server and toggle "Expose" on an account row.',
    // 详情页
    root_user_is: 'root user',
    connectivity: 'Connectivity',
    not_verified_yet: 'Not verified yet — click "Test Connection" to verify reachability and root credentials',
    account_list: 'Accounts',
    username_col: 'Username',
    state: 'State',
    capabilities: 'Flags',
    expires_col: 'Expiry',
    st_active: 'Active',
    st_error: 'Error',
    st_locked: 'Locked',
    st_pending: 'Pending',
    exposed: 'Expose',
    never: 'never',
    expired_badge: 'Expired',
    set_expiry: 'Expiry',
    expiry_hint: 'RFC3339 time, e.g. 2026-12-31T23:59:59+08:00; empty = never expires',
    save: 'Save',
    edit_perms: 'Permissions',
    perms_hint: 'Per-directory grants, comma separated:',
    change_pwd: 'Password',
    new_password: 'New password',
    reset: 'Reset',
    re_provision: 'Re-provision',
    confirm_del_account: 'Delete account and remotely remove this OS user?',
    create_account: 'Create Account',
    perms_label: 'Directory permissions',
    expiry_label: 'Expiry',
    never_hint: 'empty = never expires',
    exposed_to_agent: 'Expose to agent',
    create: 'Create',
    idempotent_hint: 'If the username already exists on the server, its password is reset and the permissions above applied (idempotent).',
    // app.js 动态文案
    op_failed: 'Operation failed: ',
    testing: 'Testing…',
    conn_ok: 'Connected',
    conn_fail: 'Connection failed',
    enter_new_pwd: 'Enter a new password',
    updated: 'Updated',
    fail: 'Failed: ',
    confirm: 'Confirm'
  },
  zh: {
    brand_sub: '服务器接线台',
    logout: '退出',
    login: '登录',
    login_sub: 'ServerAgentLink · 服务器接线台',
    username: '用户名',
    password: '密码',
    login_failed: '用户名或密码错误',
    back: '← 返回服务器列表',
    servers: '服务器',
    servers_sub: '管理目标服务器，及其编码账户与逐目录权限',
    add_server: '添加服务器',
    name: '名称',
    host: '主机',
    ssh_port: 'SSH 端口',
    root_user: 'root 用户',
    root_password: 'root 密码',
    server_list: '服务器列表',
    status: '状态',
    accounts: '账户',
    actions: '操作',
    enter: '进入',
    test_conn: '测试连通',
    delete: '删除',
    confirm_del_server: '删除该服务器，并远程删除其全部账户？',
    verified: '已验证',
    unverified: '未验证',
    exposed_accounts: '已暴露给 agent 的账户',
    exposed_sub: '这些账户的 SSH 凭据会通过 MCP 提供给 agent；在服务器详情页点账户行的「暴露」即可开关。',
    server: '服务器',
    dir_perms: '目录权限',
    no_servers: '还没有服务器。在上方添加第一台目标服务器。',
    no_exposed: '暂无暴露给 agent 的账户。进入某台服务器，点账户行的「暴露」开关即可。',
    root_user_is: 'root 用户',
    connectivity: '连通性',
    not_verified_yet: '尚未验证，点击「测试连通」以验证主机可达与 root 凭据',
    account_list: '账户',
    username_col: '用户名',
    state: '状态',
    capabilities: '能力',
    expires_col: '到期',
    st_active: '正常',
    st_error: '异常',
    st_locked: '已锁定',
    st_pending: '待建户',
    exposed: '暴露',
    never: '永不',
    expired_badge: '已到期',
    set_expiry: '到期',
    expiry_hint: 'RFC3339 时刻，如 2026-12-31T23:59:59+08:00；留空 = 永不到期',
    save: '保存',
    edit_perms: '改权限',
    perms_hint: '逐目录授权，逗号分隔：',
    change_pwd: '改密码',
    new_password: '新密码',
    reset: '重置',
    re_provision: '重新建户',
    confirm_del_account: '删除账户，并远程删除该 OS 用户？',
    create_account: '新建账户',
    perms_label: '目录权限',
    expiry_label: '到期时间',
    never_hint: '留空 = 永不到期',
    exposed_to_agent: '暴露给 agent',
    create: '创建账户',
    idempotent_hint: '若用户名在服务器上已存在，将重置其密码并应用上方权限（幂等）。',
    op_failed: '操作失败：',
    testing: '测试中…',
    conn_ok: '已连通',
    conn_fail: '连接失败',
    enter_new_pwd: '请输入新密码',
    updated: '已更新',
    fail: '失败：',
    confirm: '确认'
  }
};

function salLang() {
  var v = localStorage.getItem('sal_lang');
  if (v !== 'en' && v !== 'zh') {
    v = (navigator.language || 'zh').toLowerCase().indexOf('zh') === 0 ? 'zh' : 'en';
  }
  return v;
}

function salT(key) {
  return (SAL_I18N[salLang()] || SAL_I18N.zh)[key] || SAL_I18N.zh[key] || key;
}

// 把整页所有 data-i18n 文案替换为当前语言。
function salApplyI18n(root) {
  root = root || document;
  document.documentElement.lang = salLang() === 'zh' ? 'zh' : 'en';
  var els = root.querySelectorAll('[data-i18n]');
  for (var i = 0; i < els.length; i++) {
    els[i].textContent = salT(els[i].getAttribute('data-i18n'));
  }
  var phs = root.querySelectorAll('[data-i18n-placeholder]');
  for (var j = 0; j < phs.length; j++) {
    phs[j].setAttribute('placeholder', salT(phs[j].getAttribute('data-i18n-placeholder')));
  }
  var tps = root.querySelectorAll('[data-i18n-title]');
  for (var k = 0; k < tps.length; k++) {
    tps[k].setAttribute('title', salT(tps[k].getAttribute('data-i18n-title')));
  }
}

// 导航栏语言切换按钮（中文/EN 互切后刷新，文案全部走 data-i18n）。
function salToggleLang() {
  localStorage.setItem('sal_lang', salLang() === 'zh' ? 'en' : 'zh');
  location.reload();
}

document.addEventListener('DOMContentLoaded', function () {
  salApplyI18n(document);
  var btn = document.getElementById('lang-toggle');
  if (btn) {
    btn.textContent = salLang() === 'zh' ? 'EN' : '中文';
    btn.addEventListener('click', salToggleLang);
  }
});
