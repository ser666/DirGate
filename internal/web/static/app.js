// DirGate 前端辅助逻辑。全部操作走 fetch + double-submit CSRF，无外部 CDN 依赖。

function dgtCookie(name) {
  var m = document.cookie.match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
  return m ? decodeURIComponent(m[1]) : '';
}

function dgtCsrfHeaders(extra) {
  var h = Object.assign({}, extra || {});
  var t = dgtCookie('dg_csrf');
  if (t) h['X-CSRF-Token'] = t;
  return h;
}

// 通用 fetch：带 CSRF 头；2xx 解析 JSON 返回，非 2xx 抛出服务端 error 信息。
function dgtFetch(method, url, body) {
  return fetch(url, {
    method: method,
    headers: dgtCsrfHeaders(body ? { 'Content-Type': 'application/json' } : {}),
    body: body ? JSON.stringify(body) : undefined,
  }).then(function (r) {
    if (r.status === 204) return null;
    return r.json().catch(function () { return {}; }).then(function (data) {
      if (!r.ok) throw new Error((data && data.error) || ('HTTP ' + r.status));
      return data;
    });
  });
}

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
  });
}

// 把「/path=mode,/path=mode」解析为权限数组。
function parsePerms(str) {
  return (str || '').split(',').map(function (s) { return s.trim(); }).filter(Boolean).map(function (s) {
    var kv = s.split('=');
    return { path: kv[0].trim(), mode: (kv[1] || 'rw').trim() };
  });
}

// 通用 JSON 表单提交。onOk 缺省为刷新页面。
window.dgtSubmit = function (formId, url, toBody, onOk, method) {
  var form = document.getElementById(formId);
  if (!form) return;
  form.addEventListener('submit', function (e) {
    e.preventDefault();
    var fd = new FormData(form);
    dgtFetch(method || 'POST', url, toBody(fd))
      .then(function () { if (onOk) onOk(); else location.reload(); })
      .catch(function (err) { alert(dgtT('op_failed') + err.message); });
  });
};

// 连通性测试：调用 /api/servers/{id}/test，把结果写进 data-target 指向的元素。
function dgtTest(btn) {
  var id = btn.getAttribute('data-id');
  var target = document.getElementById(btn.getAttribute('data-target'));
  var original = btn.textContent;
  btn.disabled = true;
  btn.textContent = dgtT('testing');
  dgtFetch('POST', '/api/servers/' + id + '/test', {})
    .then(function (res) {
      if (target) {
        if (res.connected) {
          target.innerHTML = '<span class="dot dot-ok"></span>' + dgtT('conn_ok') +
            (res.host_key ? ' · <span class="mono fp">' + esc(res.host_key) + '</span>' : '');
        } else {
          target.innerHTML = '<span class="dot dot-bad"></span>' + dgtT('conn_fail') + ' · <span class="mono err">' + esc(res.error) + '</span>';
        }
      }
    })
    .catch(function (err) {
      if (target) target.innerHTML = '<span class="dot dot-bad"></span>' + dgtT('conn_fail') + ' · <span class="mono err">' + esc(err.message) + '</span>';
    })
    .finally(function () { btn.disabled = false; btn.textContent = dgtT('test_conn'); });
}

// 退出登录。
(function () {
  var lo = document.getElementById('logout');
  if (lo) lo.addEventListener('submit', function (e) {
    e.preventDefault();
    dgtFetch('POST', '/api/logout', {}).then(function () { location.href = '/login'; });
  });
})();

// data-action 按钮：删服务器/删账户/重新建户（测试连通单独处理）。
document.addEventListener('click', function (ev) {
  var btn = ev.target.closest('[data-action]');
  if (!btn) return;
  var action = btn.getAttribute('data-action');
  if (action === 'test-server') { dgtTest(btn); return; }

  var id = btn.getAttribute('data-id');
  if (action === 'toggle-flag') {
    var flag = btn.getAttribute('data-flag');
    var body = {};
    body[flag] = !btn.classList.contains('on');
    dgtFetch('PUT', '/api/accounts/' + id, body)
      .then(function () { location.reload(); })
      .catch(function (err) { alert(dgtT('op_failed') + err.message); });
    return;
  }

  var url = '', method = 'POST', confirmKey = '';
  if (action === 'delete-server') { url = '/api/servers/' + id; method = 'DELETE'; confirmKey = 'confirm_del_server'; }
  else if (action === 'delete-account') { url = '/api/accounts/' + id; method = 'DELETE'; confirmKey = 'confirm_del_account'; }
  else if (action === 'provision') { url = '/api/accounts/' + id + '/provision'; }

  if (confirmKey && !window.confirm(dgtT(confirmKey))) return;
  dgtFetch(method, url).then(function () { location.reload(); })
    .catch(function (err) { alert(dgtT('op_failed') + err.message); });
});

// 行内「改权限」「改密码」与「到期」表单。
document.addEventListener('submit', function (ev) {
  var f = ev.target;
  if (f.classList.contains('perm-form')) {
    ev.preventDefault();
    var msg = f.querySelector('.msg');
    dgtFetch('PUT', '/api/accounts/' + f.getAttribute('data-account') + '/permissions',
      parsePerms(f.elements['perms'].value))
      .then(function () { location.reload(); })
      .catch(function (err) { msg.textContent = '失败：' + err.message; msg.classList.add('err'); });
  } else if (f.classList.contains('pwd-form')) {
    ev.preventDefault();
    var m2 = f.querySelector('.msg');
    var pw = f.elements['password'].value;
    if (!pw) { m2.textContent = dgtT('enter_new_pwd'); m2.classList.add('err'); return; }
    dgtFetch('PUT', '/api/accounts/' + f.getAttribute('data-account') + '/password', { password: pw })
      .then(function () { m2.textContent = dgtT('updated'); m2.classList.remove('err'); f.elements['password'].value = ''; })
      .catch(function (err) { m2.textContent = dgtT('fail') + err.message; m2.classList.add('err'); });
  } else if (f.classList.contains('exp-form')) {
    ev.preventDefault();
    var m3 = f.querySelector('.msg');
    dgtFetch('PUT', '/api/accounts/' + f.getAttribute('data-account'),
      { expires_at: (f.elements['expires_at'].value || '').trim() })
      .then(function () { location.reload(); })
      .catch(function (err) { m3.textContent = '失败：' + err.message; m3.classList.add('err'); });
  }
});
