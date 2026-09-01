package oauthui

const loginPage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Sign in to RemoteOps</title></head>
<body><main><h1>Sign in to RemoteOps</h1>{{if .Error}}<p role="alert">{{.Error}}</p>{{end}}
<form method="post" action="/oauth/login"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="transaction" value="{{.Transaction}}">
<label>Email <input name="email" type="email" autocomplete="username" maxlength="320" required></label>
<label>Password <input name="password" type="password" autocomplete="current-password" maxlength="1024" required></label>
<button type="submit">Sign in</button></form></main></body></html>`

const passwordPage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Change RemoteOps password</title></head>
<body><main><h1>Change password</h1><p>Signed in as {{.Email}}</p>{{if .Error}}<p role="alert">{{.Error}}</p>{{end}}
<form method="post" action="/oauth/account/password"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="transaction" value="{{.Transaction}}">
<label>Current password <input name="current_password" type="password" autocomplete="current-password" maxlength="1024" required></label>
<label>New password <input name="new_password" type="password" autocomplete="new-password" maxlength="1024" required></label>
<label>Confirm new password <input name="confirm_password" type="password" autocomplete="new-password" maxlength="1024" required></label>
<button type="submit">Change password</button></form></main></body></html>`

const adminPage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>RemoteOps users</title></head>
<body><main><h1>RemoteOps users</h1><p>Signed in as {{.Actor.Email}}</p>
<section><h2>Create user</h2><form method="post" action="/oauth/admin/users/create"><input type="hidden" name="csrf" value="{{.CSRF}}">
<label>Email <input name="email" type="email" maxlength="320" required></label><label>Temporary password <input name="new_password" type="password" maxlength="1024" required></label>
<label>Role <select name="role"><option>viewer</option><option>operator</option><option>admin</option></select></label>
<label>Your password <input name="current_password" type="password" autocomplete="current-password" maxlength="1024" required></label><button>Create</button></form></section>
{{range .Users}}<section><h2>{{.Email}}</h2><p>Role: {{.Role}}; enabled: {{.Enabled}}</p>
<form method="post" action="/oauth/admin/users/{{.ID}}/update"><input type="hidden" name="csrf" value="{{$.CSRF}}"><label>Role <select name="role"><option{{if roleEq .Role "viewer"}} selected{{end}}>viewer</option><option{{if roleEq .Role "operator"}} selected{{end}}>operator</option><option{{if roleEq .Role "admin"}} selected{{end}}>admin</option></select></label><label>Enabled <input type="checkbox" name="enabled"{{if .Enabled}} checked{{end}}></label><label>Your password <input name="current_password" type="password" maxlength="1024" required></label><button>Update</button></form>
<form method="post" action="/oauth/admin/users/{{.ID}}/reset-password"><input type="hidden" name="csrf" value="{{$.CSRF}}"><label>Temporary password <input name="new_password" type="password" maxlength="1024" required></label><label>Your password <input name="current_password" type="password" maxlength="1024" required></label><button>Reset password</button></form>
<form method="post" action="/oauth/admin/users/{{.ID}}/revoke-sessions"><input type="hidden" name="csrf" value="{{$.CSRF}}"><label>Your password <input name="current_password" type="password" maxlength="1024" required></label><button>Revoke sessions</button></form></section>{{end}}
<form method="post" action="/oauth/logout"><input type="hidden" name="csrf" value="{{.CSRF}}"><button>Sign out</button></form></main></body></html>`
