// ====================== 智慧农田管理系统后端服务 ======================

const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = 'smart-farm-secret-key-2024';
const DATA_FILE = path.join(__dirname, 'data.json');

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ====================== 工具函数 ======================

// 读取数据文件
function readData() {
  try {
    const data = fs.readFileSync(DATA_FILE, 'utf8');
    return JSON.parse(data);
  } catch (err) {
    console.error('读取数据文件失败:', err.message);
    return {};
  }
}

// 写入数据文件
function writeData(data) {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), 'utf8');
    return true;
  } catch (err) {
    console.error('写入数据文件失败:', err.message);
    return false;
  }
}

// 获取新ID
function getNextId(list) {
  if (!list || list.length === 0) return 1;
  return Math.max(...list.map(item => item.id)) + 1;
}

// 获取当前时间字符串
function getCurrentTime() {
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const day = String(now.getDate()).padStart(2, '0');
  const hours = String(now.getHours()).padStart(2, '0');
  const minutes = String(now.getMinutes()).padStart(2, '0');
  const seconds = String(now.getSeconds()).padStart(2, '0');
  return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
}

// 统一成功响应
function success(res, data = null, message = '操作成功') {
  res.json({ code: 200, message, data });
}

// 统一失败响应
function fail(res, message = '操作失败', code = 400) {
  res.status(code).json({ code, message, data: null });
}

// 分页处理
function paginate(list, current = 1, size = 10) {
  const pageNum = parseInt(current);
  const pageSize = parseInt(size);
  const total = list.length;
  const start = (pageNum - 1) * pageSize;
  const records = list.slice(start, start + pageSize);
  return { current: pageNum, size: pageSize, total, records };
}

// 记录操作日志
function addOperationLog(userId, username, operation, module, ip = '127.0.0.1') {
  const data = readData();
  if (!data.operationLogs) data.operationLogs = [];
  const log = {
    id: getNextId(data.operationLogs),
    userId,
    username,
    operation,
    module,
    ip,
    createTime: getCurrentTime()
  };
  data.operationLogs.push(log);
  writeData(data);
}

// 获取客户端IP
function getClientIp(req) {
  return req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.ip || '127.0.0.1';
}

// ====================== JWT 认证中间件 ======================

function authMiddleware(req, res, next) {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) {
    return fail(res, '未登录或token已过期', 401);
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return fail(res, 'token验证失败', 401);
  }
}

function adminMiddleware(req, res, next) {
  const data = readData();
  const user = data.users.find(u => u.id === req.user.userId);
  if (!user || user.roleId !== 1) {
    return fail(res, '无权限操作，仅管理员可执行此操作', 403);
  }
  next();
}

function hasPermission(userId, permissionCode) {
  const data = readData();
  const user = data.users.find(u => u.id === userId);
  if (!user) return false;
  if (user.roleId === 1) return true;
  if (user.permissions && Array.isArray(user.permissions) && user.permissions.length > 0) {
    if (user.permissions[0] === '*') return true;
    return user.permissions.includes(permissionCode);
  }
  const role = data.roles.find(r => r.id === user.roleId);
  if (!role || !role.permissions) return false;
  if (role.permissions[0] === '*') return true;
  return role.permissions.includes(permissionCode);
}

function permissionMiddleware(permissionCode) {
  return function(req, res, next) {
    if (hasPermission(req.user.userId, permissionCode)) {
      next();
    } else {
      return fail(res, '无权限执行此操作', 403);
    }
  };
}

// ====================== 模块一：系统权限管理 API ======================

// 1. 登录
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  const data = readData();
  const user = data.users.find(u => u.username === username && u.password === password);
  if (!user) {
    return fail(res, '用户名或密码错误');
  }
  if (user.status !== 1) {
    return fail(res, '账号已被禁用');
  }
  const token = jwt.sign({ userId: user.id, username: user.username, roleId: user.roleId }, JWT_SECRET, { expiresIn: '7d' });
  addOperationLog(user.id, user.username, '登录系统', '系统管理', getClientIp(req));
  const safeUser = {
    id: user.id,
    username: user.username,
    realName: user.realName,
    roleId: user.roleId,
    status: user.status,
    phone: user.phone,
    email: user.email,
    createTime: user.createTime
  };
  success(res, { token, user: safeUser }, '登录成功');
});

// 2. 注册
app.post('/api/auth/register', (req, res) => {
  const { username, password, realName, phone, email } = req.body;
  const data = readData();
  if (data.users.find(u => u.username === username)) {
    return fail(res, '用户名已存在');
  }
  const newUser = {
    id: getNextId(data.users),
    username,
    password,
    realName: realName || username,
    roleId: 2,
    status: 1,
    phone: phone || '',
    email: email || '',
    createTime: getCurrentTime()
  };
  data.users.push(newUser);
  writeData(data);
  addOperationLog(newUser.id, newUser.username, '注册账号', '系统管理', getClientIp(req));
  const { password: _, ...registeredUser } = newUser;
  success(res, registeredUser, '注册成功');
});

// 3. 获取当前用户信息
app.get('/api/auth/userinfo', authMiddleware, (req, res) => {
  const data = readData();
  const user = data.users.find(u => u.id === req.user.userId);
  if (!user) {
    return fail(res, '用户不存在');
  }
  const role = data.roles.find(r => r.id === user.roleId);
  const { password, ...safeUser } = user;
  success(res, { ...safeUser, roleName: role?.roleName || '' });
});

// 4. 修改密码
app.put('/api/auth/password', authMiddleware, (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const data = readData();
  const userIndex = data.users.findIndex(u => u.id === req.user.userId);
  if (userIndex === -1) {
    return fail(res, '用户不存在');
  }
  if (data.users[userIndex].password !== oldPassword) {
    return fail(res, '原密码错误');
  }
  data.users[userIndex].password = newPassword;
  writeData(data);
  addOperationLog(req.user.userId, req.user.username, '修改密码', '系统管理', getClientIp(req));
  success(res, null, '密码修改成功');
});

// 5. 修改个人信息
app.put('/api/auth/profile', authMiddleware, (req, res) => {
  const { realName, phone, email } = req.body;
  const data = readData();
  const userIndex = data.users.findIndex(u => u.id === req.user.userId);
  if (userIndex === -1) {
    return fail(res, '用户不存在');
  }
  if (realName !== undefined) data.users[userIndex].realName = realName;
  if (phone !== undefined) data.users[userIndex].phone = phone;
  if (email !== undefined) data.users[userIndex].email = email;
  writeData(data);
  addOperationLog(req.user.userId, req.user.username, '修改个人信息', '系统管理', getClientIp(req));
  const { password, ...safeUser } = data.users[userIndex];
  success(res, safeUser, '信息修改成功');
});

// 6. 用户列表（分页+搜索）
app.get('/api/user/list', authMiddleware, permissionMiddleware('user:view'), (req, res) => {
  const { current = 1, size = 10, keyword = '', roleId, status } = req.query;
  const data = readData();
  const currentUser = data.users.find(u => u.id === req.user.userId);
  const isAdmin = currentUser && (currentUser.roleId === 1 || currentUser.roleId === 3);
  if (!isAdmin) {
    return fail(res, '无权限查看用户列表', 403);
  }
  let list = [...data.users];
  if (keyword) {
    list = list.filter(u => u.username.includes(keyword) || u.realName.includes(keyword) || u.phone.includes(keyword));
  }
  if (roleId) {
    list = list.filter(u => u.roleId === parseInt(roleId));
  }
  if (status !== undefined && status !== '') {
    list = list.filter(u => u.status === parseInt(status));
  }
  list = list.map(u => {
    const role = data.roles.find(r => r.id === u.roleId);
    const { password, ...safeUser } = u;
    return { ...safeUser, roleName: role?.roleName || '' };
  });
  list.sort((a, b) => b.id - a.id);
  success(res, paginate(list, current, size));
});

// 7. 新增用户
app.post('/api/user/add', authMiddleware, permissionMiddleware('user:add'), (req, res) => {
  const { username, password, realName, roleId, status, phone, email } = req.body;
  const data = readData();
  if (data.users.find(u => u.username === username)) {
    return fail(res, '用户名已存在');
  }
  const currentUser = data.users.find(u => u.id === req.user.userId);
  if (!currentUser) {
    return fail(res, '当前用户不存在', 401);
  }
  const isSuperAdmin = currentUser.roleId === 1;
  const isAdmin = currentUser.roleId === 1 || currentUser.roleId === 3;
  if (!isAdmin) {
    return fail(res, '无权限新增用户', 403);
  }
  if (!isSuperAdmin && roleId === 1) {
    return fail(res, '无权限创建高级管理员账号');
  }
  const newUser = {
    id: getNextId(data.users),
    username,
    password: password || '123456',
    realName: realName || username,
    roleId: roleId || 2,
    status: status !== undefined ? status : 1,
    phone: phone || '',
    email: email || '',
    createTime: getCurrentTime()
  };
  data.users.push(newUser);
  writeData(data);
  addOperationLog(req.user.userId, req.user.username, `新增用户: ${username}`, '系统管理', getClientIp(req));
  const { password: _, ...safeNewUser } = newUser;
  success(res, safeNewUser, '新增成功');
});

// 8. 更新用户
app.put('/api/user/update', authMiddleware, permissionMiddleware('user:edit'), (req, res) => {
  const { id, realName, roleId, status, phone, email } = req.body;
  const data = readData();
  const userIndex = data.users.findIndex(u => u.id === id);
  if (userIndex === -1) {
    return fail(res, '用户不存在');
  }
  const currentUser = data.users.find(u => u.id === req.user.userId);
  if (!currentUser) {
    return fail(res, '当前用户不存在', 401);
  }
  const isSuperAdmin = currentUser.roleId === 1;
  const isAdmin = currentUser.roleId === 1 || currentUser.roleId === 3;
  const targetUser = data.users[userIndex];
  const targetIsSuperAdmin = targetUser.roleId === 1;
  const isSelf = id === req.user.userId;
  if (!isSuperAdmin) {
    if (targetIsSuperAdmin) {
      return fail(res, '无权限操作高级管理员账号');
    }
    if (isSelf && status !== undefined && status !== 1) {
      return fail(res, '不能禁用自己的账号');
    }
    if (roleId !== undefined && (roleId === 1 || targetUser.roleId === 1)) {
      return fail(res, '无权限修改管理员角色');
    }
  }
  if (realName !== undefined) data.users[userIndex].realName = realName;
  if (roleId !== undefined) data.users[userIndex].roleId = roleId;
  if (status !== undefined) {
    if (!isAdmin) {
      return fail(res, '无权限修改用户状态');
    }
    data.users[userIndex].status = status;
  }
  if (phone !== undefined) data.users[userIndex].phone = phone;
  if (email !== undefined) data.users[userIndex].email = email;
  writeData(data);
  addOperationLog(req.user.userId, req.user.username, `更新用户: ${data.users[userIndex].username}`, '系统管理', getClientIp(req));
  const { password, ...updatedUser } = data.users[userIndex];
  success(res, updatedUser, '更新成功');
});

// 8.1 获取用户权限
app.get('/api/user/permissions/:id', authMiddleware, permissionMiddleware('user:edit'), (req, res) => {
  const id = parseInt(req.params.id);
  const data = readData();
  const currentUser = data.users.find(u => u.id === req.user.userId);
  const isAdmin = currentUser && (currentUser.roleId === 1 || currentUser.roleId === 3);
  if (!isAdmin) {
    return fail(res, '无权限查看用户权限', 403);
  }
  const user = data.users.find(u => u.id === id);
  if (!user) {
    return fail(res, '用户不存在');
  }
  if (!currentUser || currentUser.roleId !== 1) {
    if (user.roleId === 1) {
      return fail(res, '无权限查看高级管理员权限');
    }
  }
  const role = data.roles.find(r => r.id === user.roleId);
  success(res, {
    userId: user.id,
    username: user.username,
    realName: user.realName,
    roleId: user.roleId,
    roleName: role?.roleName || '',
    userPermissions: user.permissions || [],
    rolePermissions: role?.permissions || [],
    useUserPermissions: user.permissions && Array.isArray(user.permissions) && user.permissions.length > 0
  });
});

// 8.2 保存用户权限
app.put('/api/user/permissions/:id', authMiddleware, adminMiddleware, (req, res) => {
  const id = parseInt(req.params.id);
  const { permissions } = req.body;
  const data = readData();
  const userIndex = data.users.findIndex(u => u.id === id);
  if (userIndex === -1) {
    return fail(res, '用户不存在');
  }
  const targetUser = data.users[userIndex];
  if (targetUser.roleId === 1 && id !== req.user.userId) {
    return fail(res, '无权限修改高级管理员权限');
  }
  if (permissions.some(p => p.includes(':delete'))) {
    return fail(res, '无权限分配删除权限');
  }
  if (permissions && permissions.length > 0) {
    data.users[userIndex].permissions = permissions;
  } else {
    delete data.users[userIndex].permissions;
  }
  writeData(data);
  addOperationLog(req.user.userId, req.user.username, `分配用户权限: ${targetUser.username}`, '系统管理', getClientIp(req));
  success(res, null, '权限分配成功');
});

// 9. 删除用户
app.delete('/api/user/:id', authMiddleware, adminMiddleware, (req, res) => {
  const id = parseInt(req.params.id);
  const data = readData();
  const userIndex = data.users.findIndex(u => u.id === id);
  if (userIndex === -1) {
    return fail(res, '用户不存在');
  }
  const currentUser = data.users.find(u => u.id === req.user.userId);
  if (!currentUser) {
    return fail(res, '当前用户不存在', 401);
  }
  const isSuperAdmin = currentUser.roleId === 1;
  const targetIsSuperAdmin = data.users[userIndex].roleId === 1;
  if (!isSuperAdmin && targetIsSuperAdmin) {
    return fail(res, '无权限删除高级管理员账号');
  }
  if (id === req.user.userId) {
    return fail(res, '不能删除自己');
  }
  const deletedUser = data.users.splice(userIndex, 1)[0];
  writeData(data);
  addOperationLog(req.user.userId, req.user.username, `删除用户: ${deletedUser.username}`, '系统管理', getClientIp(req));
  success(res, null, '删除成功');
});

// 10. 角色列表
app.get('/api/role/list', authMiddleware, permissionMiddleware('user:view'), (req, res) => {
  const data = readData();
  const currentUser = data.users.find(u => u.id === req.user.userId);
  const isAdmin = currentUser && (currentUser.roleId === 1 || currentUser.roleId === 3);
  if (!isAdmin) {
    return fail(res, '无权限查看角色列表', 403);
  }
  const list = data.roles.map(r => ({
    id: r.id,
    roleName: r.roleName,
    roleCode: r.roleCode,
    description: r.description,
    permissionCount: r.permissions && r.permissions[0] === '*' ? '全部' : (r.permissions ? r.permissions.length : 0),
    userCount: data.users.filter(u => u.roleId === r.id).length,
    permissions: r.permissions || [],
    createTime: r.createTime || ''
  }));
  success(res, list);
});

// 10.2 获取角色下的用户列表
app.get('/api/role/users/:roleId', authMiddleware, permissionMiddleware('user:view'), (req, res) => {
  const roleId = parseInt(req.params.roleId);
  const data = readData();
  const currentUser = data.users.find(u => u.id === req.user.userId);
  const isAdmin = currentUser && (currentUser.roleId === 1 || currentUser.roleId === 3);
  if (!isAdmin) {
    return fail(res, '无权限查看角色用户列表', 403);
  }
  const role = data.roles.find(r => r.id === roleId);
  const users = data.users.filter(u => u.roleId === roleId).map(u => ({
    id: u.id,
    username: u.username,
    realName: u.realName,
    phone: u.phone,
    email: u.email,
    status: u.status,
    roleId: u.roleId,
    roleName: role?.roleName || '',
    permissions: u.permissions || [],
    createTime: u.createTime
  }));
  success(res, users);
});

// 10.1 获取权限树
app.get('/api/permission/tree', authMiddleware, permissionMiddleware('user:view'), (req, res) => {
  const data = readData();
  const currentUser = data.users.find(u => u.id === req.user.userId);
  const isAdmin = currentUser && (currentUser.roleId === 1 || currentUser.roleId === 3);
  if (!isAdmin) {
    return fail(res, '无权限查看权限树', 403);
  }
  success(res, data.permissions || []);
});

// 10.2 分配角色权限
app.put('/api/role/permissions/:id', authMiddleware, adminMiddleware, (req, res) => {
  const id = parseInt(req.params.id);
  const { permissions } = req.body;
  if (!Array.isArray(permissions)) {
    return fail(res, '权限格式错误');
  }
  const data = readData();
  const roleIndex = data.roles.findIndex(r => r.id === id);
  if (roleIndex === -1) {
    return fail(res, '角色不存在');
  }
  if (id === 1) {
    return fail(res, '管理员角色权限不可修改');
  }
  const filteredPerms = permissions.filter(p => !p.includes(':delete'));
  data.roles[roleIndex].permissions = filteredPerms;
  writeData(data);
  addOperationLog(req.user.userId, req.user.username, `分配角色权限：${data.roles[roleIndex].roleName}`, '系统管理', getClientIp(req));
  success(res, null, '权限分配成功');
});

// 10.3 获取当前用户权限
app.get('/api/auth/permissions', authMiddleware, (req, res) => {
  const data = readData();
  const user = data.users.find(u => u.id === req.user.userId);
  if (!user) {
    return fail(res, '用户不存在', 401);
  }
  if (user.roleId === 1) {
    return success(res, { permissions: ['*'], roleName: '高级管理员', permSource: 'role' });
  }
  const role = data.roles.find(r => r.id === user.roleId);
  let perms = [];
  let permSource = 'role';
  if (user.permissions && Array.isArray(user.permissions) && user.permissions.length > 0) {
    if (user.permissions[0] === '*') {
      perms = ['*'];
    } else {
      perms = user.permissions;
    }
    permSource = 'user';
  } else if (role) {
    if (role.permissions && role.permissions[0] === '*') {
      perms = ['*'];
    } else {
      perms = role.permissions || [];
    }
  }
  success(res, { permissions: perms, roleName: role ? role.roleName : '', permSource });
});

// 11. 操作日志列表（分页+搜索）
app.get('/api/log/list', authMiddleware, permissionMiddleware('log:view'), (req, res) => {
  const { current = 1, size = 10, keyword = '', module, operator } = req.query;
  const data = readData();
  const currentUser = data.users.find(u => u.id === req.user.userId);
  const isAdmin = currentUser && (currentUser.roleId === 1 || currentUser.roleId === 3);
  if (!isAdmin) {
    return fail(res, '无权限查看操作日志', 403);
  }
  let list = [...data.operationLogs];
  if (keyword) {
    list = list.filter(l => l.username.includes(keyword) || l.operation.includes(keyword));
  }
  if (module) {
    list = list.filter(l => l.module === module);
  }
  if (operator) {
    list = list.filter(l => l.username.includes(operator));
  }
  list = list.map(l => {
    let type = '';
    const op = l.operation;
    if (op.includes('删除')) type = 'delete';
    else if (op.includes('新增') || op.includes('创建') || op.includes('添加') || op.includes('录入') || op.includes('入库') || op.includes('领用')) type = 'create';
    else if (op.includes('更新') || op.includes('编辑') || op.includes('修改') || op.includes('状态')) type = 'update';
    else if (op.includes('登录') || op.includes('注册')) type = 'login';
    else type = 'query';
    return {
      id: l.id,
      operator: l.username,
      module: l.module,
      type: type,
      content: l.operation,
      ip: l.ip,
      createdAt: l.createTime,
      userId: l.userId
    };
  });
  list.sort((a, b) => b.id - a.id);
  success(res, paginate(list, current, size));
});

// ====================== 模块二：地块与作物档案管理 API ======================

// 12. 地块列表（分页+搜索）
app.get('/api/field/list', authMiddleware, permissionMiddleware('field:view'), (req, res) => {
  const { current = 1, size = 10, keyword = '', status } = req.query;
  const data = readData();
  let list = [...data.fields].map(f => ({ ...f, name: f.fieldName }));
  if (keyword) {
    list = list.filter(f => f.fieldName.includes(keyword) || f.location.includes(keyword));
  }
  if (status !== undefined && status !== '') {
    list = list.filter(f => f.status === parseInt(status) || f.status === status);
  }
  list.sort((a, b) => b.id - a.id);
  success(res, paginate(list, current, size));
});

// 13. 新增地块
app.post('/api/field/add', authMiddleware, permissionMiddleware('field:add'), (req, res) => {
  const { fieldName, area, location, soilType, irrigationType, status, remark } = req.body;
  const data = readData();
  const newField = {
    id: getNextId(data.fields),
    fieldName,
    area: parseFloat(area) || 0,
    location: location || '',
    soilType: soilType || '',
    irrigationType: irrigationType || '',
    status: status !== undefined ? status : 1,
    remark: remark || '',
    createTime: getCurrentTime()
  };
  data.fields.push(newField);
  writeData(data);
  addOperationLog(req.user.userId, req.user.username, `新增地块: ${fieldName}`, '地块管理', getClientIp(req));
  success(res, newField, '新增成功');
});

// 14. 更新地块
app.put('/api/field/update', authMiddleware, permissionMiddleware('field:edit'), (req, res) => {
  const { id, fieldName, area, location, soilType, irrigationType, status, remark } = req.body;
  const data = readData();
  const fieldIndex = data.fields.findIndex(f => f.id === id);
  if (fieldIndex === -1) {
    return fail(res, '地块不存在');
  }
  if (fieldName !== undefined) data.fields[fieldIndex].fieldName = fieldName;
  if (area !== undefined) data.fields[fieldIndex].area = parseFloat(area);
  if (location !== undefined) data.fields[fieldIndex].location = location;
  if (soilType !== undefined) data.fields[fieldIndex].soilType = soilType;
  if (irrigationType !== undefined) data.fields[fieldIndex].irrigationType = irrigationType;
  if (status !== undefined) data.fields[fieldIndex].status = status;
  if (remark !== undefined) data.fields[fieldIndex].remark = remark;
  writeData(data);
  addOperationLog(req.user.userId, req.user.username, `更新地块: ${data.fields[fieldIndex].fieldName}`, '地块管理', getClientIp(req));
  success(res, data.fields[fieldIndex], '更新成功');
});

// 15. 删除地块
app.delete('/api/field/:id', authMiddleware, adminMiddleware, (req, res) => {
  const id = parseInt(req.params.id);
  const data = readData();
  const fieldIndex = data.fields.findIndex(f => f.id === id);
  if (fieldIndex === -1) {
    return fail(res, '地块不存在');
  }
  const deletedField = data.fields.splice(fieldIndex, 1)[0];
  writeData(data);
  addOperationLog(req.user.userId, req.user.username, `删除地块: ${deletedField.fieldName}`, '地块管理', getClientIp(req));
  success(res, null, '删除成功');
});

// 16. 作物品种列表（分页+搜索）
app.get('/api/crop/list', authMiddleware, permissionMiddleware('crop:view'), (req, res) => {
  const { current = 1, size = 10, keyword = '', cropType } = req.query;
  const data = readData();
  let list = [...data.crops].map(c => ({ ...c, name: c.cropName, variety: c.cropType }));
  if (keyword) {
    list = list.filter(c => c.cropName.includes(keyword));
  }
  if (cropType) {
    list = list.filter(c => c.cropType === cropType);
  }
  list.sort((a, b) => b.id - a.id);
  success(res, paginate(list, current, size));
});

// 17. 新增作物品种
app.post('/api/crop/add', authMiddleware, permissionMiddleware('crop:add'), (req, res) => {
  const { cropName, cropType, growthCycle, suitableSeason, remark } = req.body;
  const data = readData();
  const newCrop = {
    id: getNextId(data.crops),
    cropName,
    cropType: cropType || '',
    growthCycle: parseInt(growthCycle) || 0,
    suitableSeason: suitableSeason || '',
    remark: remark || '',
    createTime: getCurrentTime()
  };
  data.crops.push(newCrop);
  writeData(data);
  addOperationLog(req.user.userId, req.user.username, `新增作物: ${cropName}`, '作物管理', getClientIp(req));
  success(res, newCrop, '新增成功');
});

// 18. 更新作物品种
app.put('/api/crop/update', authMiddleware, permissionMiddleware('crop:edit'), (req, res) => {
  const { id, cropName, cropType, growthCycle, suitableSeason, remark } = req.body;
  const data = readData();
  const cropIndex = data.crops.findIndex(c => c.id === id);
  if (cropIndex === -1) {
    return fail(res, '作物不存在');
  }
  if (cropName !== undefined) data.crops[cropIndex].cropName = cropName;
  if (cropType !== undefined) data.crops[cropIndex].cropType = cropType;
  if (growthCycle !== undefined) data.crops[cropIndex].growthCycle = parseInt(growthCycle);
  if (suitableSeason !== undefined) data.crops[cropIndex].suitableSeason = suitableSeason;
  if (remark !== undefined) data.crops[cropIndex].remark = remark;
  writeData(data);
  addOperationLog(req.user.userId, req.user.username, `更新作物: ${data.crops[cropIndex].cropName}`, '作物管理', getClientIp(req));
  success(res, data.crops[cropIndex], '更新成功');
});

// 19. 删除作物品种
app.delete('/api/crop/:id', authMiddleware, adminMiddleware, (req, res) => {
  const id = parseInt(req.params.id);
  const data = readData();
  const cropIndex = data.crops.findIndex(c => c.id === id);
  if (cropIndex === -1) {
    return fail(res, '作物不存在');
  }
  const deletedCrop = data.crops.splice(cropIndex, 1)[0];
  writeData(data);
  addOperationLog(req.user.userId, req.user.username, `删除作物: ${deletedCrop.cropName}`, '作物管理', getClientIp(req));
  success(res, null, '删除成功');
});

// 20. 种植台账列表（分页+搜索，支持地块、作物筛选）
app.get('/api/planting/list', authMiddleware, permissionMiddleware('planting:view'), (req, res) => {
  const { current = 1, size = 10, keyword = '', fieldId, cropId, status } = req.query;
  const data = readData();
  let list = [...data.plantingRecords];
  if (keyword) {
    list = list.filter(p => p.remark.includes(keyword));
  }
  if (fieldId) {
    list = list.filter(p => p.fieldId === parseInt(fieldId));
  }
  if (cropId) {
    list = list.filter(p => p.cropId === parseInt(cropId));
  }
  if (status) {
    const statusMap = { '种植中': 'growing', '已收获': 'harvested', growing: 'growing', harvested: 'harvested' };
    const s = statusMap[status] || status;
    list = list.filter(p => p.status === s);
  }
  list = list.map(p => {
    const field = data.fields.find(f => f.id === p.fieldId);
    const crop = data.crops.find(c => c.id === p.cropId);
    const statusMap = { growing: '种植中', harvested: '已收获' };
    const status = statusMap[p.status] || p.status;
    return {
      ...p,
      fieldName: field?.fieldName || '',
      cropName: crop?.cropName || '',
      plantDate: p.plantingDate,
      expectHarvestDate: p.expectedHarvest,
      status: status
    };
  });
  list.sort((a, b) => b.id - a.id);
  success(res, paginate(list, current, size));
});

// 21. 新增种植记录（绑定地块和作物）
app.post('/api/planting/add', authMiddleware, permissionMiddleware('planting:add'), (req, res) => {
  const { fieldId, cropId, area, plantingDate, plantDate, expectedHarvest, expectHarvestDate, status, remark } = req.body;
  const statusMap = { '种植中': 'growing', '已收获': 'harvested' };
  const s = statusMap[status] || status || 'growing';
  const data = readData();
  const newRecord = {
    id: getNextId(data.plantingRecords),
    fieldId: parseInt(fieldId),
    cropId: parseInt(cropId),
    area: parseFloat(area) || 0,
    plantingDate: plantingDate || plantDate || '',
    expectedHarvest: expectedHarvest || expectHarvestDate || '',
    status: s,
    remark: remark || '',
    createTime: getCurrentTime()
  };
  data.plantingRecords.push(newRecord);
  writeData(data);
  addOperationLog(req.user.userId, req.user.username, `新增种植记录`, '种植管理', getClientIp(req));
  success(res, newRecord, '新增成功');
});

// 22. 更新种植记录
app.put('/api/planting/update', authMiddleware, permissionMiddleware('planting:edit'), (req, res) => {
  const { id, fieldId, cropId, area, plantingDate, plantDate, expectedHarvest, expectHarvestDate, status, remark } = req.body;
  const statusMap = { '种植中': 'growing', '已收获': 'harvested' };
  const data = readData();
  const recordIndex = data.plantingRecords.findIndex(p => p.id === id);
  if (recordIndex === -1) {
    return fail(res, '种植记录不存在');
  }
  if (fieldId !== undefined) data.plantingRecords[recordIndex].fieldId = parseInt(fieldId);
  if (cropId !== undefined) data.plantingRecords[recordIndex].cropId = parseInt(cropId);
  if (area !== undefined) data.plantingRecords[recordIndex].area = parseFloat(area);
  if (plantingDate !== undefined || plantDate !== undefined) data.plantingRecords[recordIndex].plantingDate = plantingDate || plantDate;
  if (expectedHarvest !== undefined || expectHarvestDate !== undefined) data.plantingRecords[recordIndex].expectedHarvest = expectedHarvest || expectHarvestDate;
  if (status !== undefined) data.plantingRecords[recordIndex].status = statusMap[status] || status;
  if (remark !== undefined) data.plantingRecords[recordIndex].remark = remark;
  writeData(data);
  addOperationLog(req.user.userId, req.user.username, `更新种植记录`, '种植管理', getClientIp(req));
  success(res, data.plantingRecords[recordIndex], '更新成功');
});

// 23. 删除种植记录
app.delete('/api/planting/:id', authMiddleware, adminMiddleware, (req, res) => {
  const id = parseInt(req.params.id);
  const data = readData();
  const recordIndex = data.plantingRecords.findIndex(p => p.id === id);
  if (recordIndex === -1) {
    return fail(res, '种植记录不存在');
  }
  data.plantingRecords.splice(recordIndex, 1);
  writeData(data);
  addOperationLog(req.user.userId, req.user.username, `删除种植记录`, '种植管理', getClientIp(req));
  success(res, null, '删除成功');
});

// 24. 地块历史种植记录
app.get('/api/planting/history/:fieldId', authMiddleware, permissionMiddleware('planting:view'), (req, res) => {
  const fieldId = parseInt(req.params.fieldId);
  const data = readData();
  let list = data.plantingRecords.filter(p => p.fieldId === fieldId);
  list = list.map(p => {
    const crop = data.crops.find(c => c.id === p.cropId);
    return { ...p, cropName: crop?.cropName || '' };
  });
  list.sort((a, b) => new Date(b.plantingDate) - new Date(a.plantingDate));
  success(res, list);
});

// ====================== 模块三：农事工单作业管理 API ======================

// 生成工单编号
function generateOrderNo() {
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const data = readData();
  const count = data.workOrders.filter(w => {
    const d = new Date(w.createTime);
    return d.getFullYear() === year && d.getMonth() + 1 === now.getMonth() + 1;
  }).length + 1;
  return `WO${year}${month}${String(count).padStart(3, '0')}`;
}

// 25. 工单列表（分页+搜索，支持状态筛选）
app.get('/api/workorder/list', authMiddleware, permissionMiddleware('workorder:view'), (req, res) => {
  const { current = 1, size = 10, keyword = '', status, type, assigneeId } = req.query;
  const data = readData();
  let list = [...data.workOrders];
  if (keyword) {
    list = list.filter(w => w.title.includes(keyword) || w.orderNo.includes(keyword));
  }
  if (status) {
    const statusMap = { '待处理': 'pending', '进行中': 'processing', '已完成': 'completed', pending: 'pending', processing: 'processing', completed: 'completed' };
    const mappedStatus = statusMap[status] || status;
    list = list.filter(w => w.status === mappedStatus);
  }
  if (type) {
    list = list.filter(w => w.type === type);
  }
  if (assigneeId) {
    list = list.filter(w => w.assigneeId === parseInt(assigneeId));
  }
  list = list.map(w => {
    const field = data.fields.find(f => f.id === w.fieldId);
    const crop = data.crops.find(c => c.id === w.cropId);
    const statusLabelMap = { pending: '待处理', processing: '进行中', completed: '已完成' };
    return {
      ...w,
      name: w.title,
      title: w.title,
      fieldName: field?.fieldName || '',
      cropName: crop?.cropName || '',
      planDate: w.planTime,
      planTime: w.planTime,
      description: w.content,
      content: w.content,
      status: statusLabelMap[w.status] || w.status,
      statusCode: w.status
    };
  });
  list.sort((a, b) => b.id - a.id);
  success(res, paginate(list, current, size));
});

// 26. 创建工单并指派
app.post('/api/workorder/add', authMiddleware, permissionMiddleware('workorder:add'), (req, res) => {
  const { title, name, fieldId, cropId, type, content, description, assigneeId, assigneeName, priority, planTime, planDate } = req.body;
  const data = readData();
  const currentUser = data.users.find(u => u.id === req.user.userId);
  if (!currentUser) {
    return fail(res, '当前用户不存在', 401);
  }
  const isAdmin = currentUser.roleId === 1 || currentUser.roleId === 3;
  if (!isAdmin) {
    return fail(res, '无权限新增工单', 403);
  }
  const orderTitle = title || name || '';
  const orderContent = content || description || '';
  const orderPlanTime = planTime || planDate || '';
  const user = data.users.find(u => u.id === parseInt(assigneeId));
  const newOrder = {
    id: getNextId(data.workOrders),
    orderNo: generateOrderNo(),
    title: orderTitle,
    fieldId: parseInt(fieldId) || 0,
    cropId: parseInt(cropId) || 0,
    type: type || '',
    content: orderContent,
    assigneeId: parseInt(assigneeId) || 0,
    assigneeName: assigneeName || (user ? user.realName : ''),
    status: 'pending',
    priority: priority || 'medium',
    planTime: orderPlanTime,
    createTime: getCurrentTime()
  };
  data.workOrders.push(newOrder);
  writeData(data);
  addOperationLog(req.user.userId, req.user.username, `创建工单: ${orderTitle}`, '工单管理', getClientIp(req));
  success(res, newOrder, '创建成功');
});

// 27. 更新工单
app.put('/api/workorder/update', authMiddleware, permissionMiddleware('workorder:edit'), (req, res) => {
  const { id, title, name, fieldId, cropId, type, content, description, assigneeId, assigneeName, priority, planTime, planDate, status } = req.body;
  const data = readData();
  const currentUser = data.users.find(u => u.id === req.user.userId);
  if (!currentUser) {
    return fail(res, '当前用户不存在', 401);
  }
  const isAdmin = currentUser.roleId === 1 || currentUser.roleId === 3;
  if (!isAdmin) {
    return fail(res, '无权限编辑工单', 403);
  }
  const orderIndex = data.workOrders.findIndex(w => w.id === id);
  if (orderIndex === -1) {
    return fail(res, '工单不存在');
  }
  const orderTitle = title !== undefined ? title : (name !== undefined ? name : undefined);
  const orderContent = content !== undefined ? content : (description !== undefined ? description : undefined);
  const orderPlanTime = planTime !== undefined ? planTime : (planDate !== undefined ? planDate : undefined);
  if (orderTitle !== undefined) data.workOrders[orderIndex].title = orderTitle;
  if (fieldId !== undefined) data.workOrders[orderIndex].fieldId = parseInt(fieldId);
  if (cropId !== undefined) data.workOrders[orderIndex].cropId = parseInt(cropId);
  if (type !== undefined) data.workOrders[orderIndex].type = type;
  if (orderContent !== undefined) data.workOrders[orderIndex].content = orderContent;
  if (assigneeId !== undefined) data.workOrders[orderIndex].assigneeId = parseInt(assigneeId);
  if (assigneeName !== undefined) {
    data.workOrders[orderIndex].assigneeName = assigneeName;
  } else if (assigneeId !== undefined) {
    const user = data.users.find(u => u.id === parseInt(assigneeId));
    data.workOrders[orderIndex].assigneeName = user ? user.realName : '';
  }
  if (priority !== undefined) data.workOrders[orderIndex].priority = priority;
  if (orderPlanTime !== undefined) data.workOrders[orderIndex].planTime = orderPlanTime;
  if (status !== undefined) {
    const statusMap = { '待处理': 'pending', '进行中': 'processing', '已完成': 'completed', pending: 'pending', processing: 'processing', completed: 'completed' };
    data.workOrders[orderIndex].status = statusMap[status] || status;
  }
  writeData(data);
  addOperationLog(req.user.userId, req.user.username, `更新工单: ${data.workOrders[orderIndex].title}`, '工单管理', getClientIp(req));
  success(res, data.workOrders[orderIndex], '更新成功');
});

// 28. 更新工单状态（待办/进行中/已完成）
app.put('/api/workorder/status/:id', authMiddleware, permissionMiddleware('workorder:edit'), (req, res) => {
  const id = parseInt(req.params.id);
  const { status } = req.body;
  const data = readData();
  const currentUser = data.users.find(u => u.id === req.user.userId);
  if (!currentUser) {
    return fail(res, '当前用户不存在', 401);
  }
  const isAdmin = currentUser.roleId === 1 || currentUser.roleId === 3;
  if (!isAdmin) {
    return fail(res, '无权限修改工单状态', 403);
  }
  const orderIndex = data.workOrders.findIndex(w => w.id === id);
  if (orderIndex === -1) {
    return fail(res, '工单不存在');
  }
  data.workOrders[orderIndex].status = status;
  writeData(data);
  const statusMap = { pending: '待办', processing: '进行中', completed: '已完成' };
  addOperationLog(req.user.userId, req.user.username, `更新工单状态: ${statusMap[status] || status}`, '工单管理', getClientIp(req));
  success(res, data.workOrders[orderIndex], '状态更新成功');
});

// 29. 删除工单
app.delete('/api/workorder/:id', authMiddleware, adminMiddleware, (req, res) => {
  const id = parseInt(req.params.id);
  const data = readData();
  const orderIndex = data.workOrders.findIndex(w => w.id === id);
  if (orderIndex === -1) {
    return fail(res, '工单不存在');
  }
  const deletedOrder = data.workOrders.splice(orderIndex, 1)[0];
  writeData(data);
  addOperationLog(req.user.userId, req.user.username, `删除工单: ${deletedOrder.title}`, '工单管理', getClientIp(req));
  success(res, null, '删除成功');
});

// 30. 我的待办工单
app.get('/api/workorder/mytodo', authMiddleware, permissionMiddleware('workorder:view'), (req, res) => {
  const { current = 1, size = 10, status } = req.query;
  const data = readData();
  const user = data.users.find(u => u.id === req.user.userId);
  const isAdmin = user && (user.roleId === 1 || user.roleId === 3);
  let list = data.workOrders;
  if (!isAdmin) {
    list = list.filter(w => w.assigneeId === req.user.userId);
  }
  if (status) {
    const statusMap = { '待处理': 'pending', '进行中': 'processing', '已完成': 'completed', pending: 'pending', processing: 'processing', completed: 'completed' };
    const mappedStatus = statusMap[status] || status;
    list = list.filter(w => w.status === mappedStatus);
  }
  list = list.map(w => {
    const field = data.fields.find(f => f.id === w.fieldId);
    const crop = data.crops.find(c => c.id === w.cropId);
    const assignee = data.users.find(u => u.id === w.assigneeId);
    const statusLabelMap = { pending: '待处理', processing: '进行中', completed: '已完成' };
    return {
      ...w,
      name: w.title,
      title: w.title,
      fieldName: field?.fieldName || '',
      cropName: crop?.cropName || '',
      planDate: w.planTime,
      planTime: w.planTime,
      description: w.content,
      content: w.content,
      assigneeName: w.assigneeName || assignee?.realName || '',
      status: statusLabelMap[w.status] || w.status,
      statusCode: w.status
    };
  });
  list.sort((a, b) => b.id - a.id);
  success(res, paginate(list, current, size));
});

// 31. 提交作业登记
app.post('/api/workorder/submit/:id', authMiddleware, permissionMiddleware('workorder:view'), (req, res) => {
  const id = parseInt(req.params.id);
  const { operationDate, workHours, content, weather, temperature } = req.body;
  const data = readData();
  const currentUser = data.users.find(u => u.id === req.user.userId);
  if (!currentUser) {
    return fail(res, '当前用户不存在', 401);
  }
  const isAdmin = currentUser.roleId === 1 || currentUser.roleId === 3;
  const orderIndex = data.workOrders.findIndex(w => w.id === id);
  if (orderIndex === -1) {
    return fail(res, '工单不存在');
  }
  const order = data.workOrders[orderIndex];
  if (!isAdmin && order.assigneeId !== req.user.userId) {
    return fail(res, '无权限提交此工单的作业登记', 403);
  }
  const newOperation = {
    id: getNextId(data.farmOperations),
    workOrderId: id,
    fieldId: order.fieldId,
    cropId: order.cropId,
    type: order.type,
    operatorId: req.user.userId,
    operatorName: req.user.username,
    operationDate: operationDate || getCurrentTime(),
    workHours: parseFloat(workHours) || 0,
    content: content || '',
    weather: weather || '',
    temperature: parseFloat(temperature) || 0,
    createTime: getCurrentTime()
  };
  data.farmOperations.push(newOperation);
  data.workOrders[orderIndex].status = 'completed';
  writeData(data);
  addOperationLog(req.user.userId, req.user.username, `提交作业登记: ${order.title}`, '作业管理', getClientIp(req));
  success(res, newOperation, '提交成功');
});

// 32. 病虫害防治记录列表
app.get('/api/pest/list', authMiddleware, permissionMiddleware('pest:view'), (req, res) => {
  const { current = 1, size = 10, keyword = '', fieldId, cropId, type, startDate, endDate } = req.query;
  const data = readData();
  let list = [...data.pestRecords];
  if (keyword) {
    list = list.filter(p => p.pestName.includes(keyword) || p.treatment.includes(keyword));
  }
  if (fieldId) {
    list = list.filter(p => p.fieldId === parseInt(fieldId));
  }
  if (cropId) {
    list = list.filter(p => p.cropId === parseInt(cropId));
  }
  if (type) {
    list = list.filter(p => p.type === type);
  }
  if (startDate) {
    list = list.filter(p => p.occurDate >= startDate);
  }
  if (endDate) {
    list = list.filter(p => p.occurDate <= endDate);
  }
  list = list.map(p => {
    const field = data.fields.find(f => f.id === p.fieldId);
    const crop = data.crops.find(c => c.id === p.cropId);
    return {
      ...p,
      name: p.pestName,
      pestName: p.pestName,
      fieldName: field?.fieldName || '',
      cropName: crop?.cropName || '',
      method: p.treatment,
      treatment: p.treatment,
      dosage: p.dosage || ''
    };
  });
  list.sort((a, b) => b.id - a.id);
  success(res, paginate(list, current, size));
});

// 33. 新增病虫害记录
app.post('/api/pest/add', authMiddleware, permissionMiddleware('pest:add'), (req, res) => {
  const { fieldId, cropId, pestName, name, type, occurDate, severity, treatment, method, effect, dosage, remark } = req.body;
  const data = readData();
  const recordPestName = pestName || name || '';
  const recordTreatment = treatment || method || '';
  const newRecord = {
    id: getNextId(data.pestRecords),
    fieldId: parseInt(fieldId) || 0,
    cropId: parseInt(cropId) || 0,
    pestName: recordPestName,
    type: type || '虫害',
    occurDate: occurDate || '',
    severity: severity || 'medium',
    treatment: recordTreatment,
    effect: effect || '',
    dosage: dosage || '',
    remark: remark || '',
    createTime: getCurrentTime()
  };
  data.pestRecords.push(newRecord);
  writeData(data);
  addOperationLog(req.user.userId, req.user.username, `新增病虫害记录: ${recordPestName}`, '病虫害管理', getClientIp(req));
  success(res, newRecord, '新增成功');
});

// 34. 更新病虫害记录
app.put('/api/pest/update', authMiddleware, permissionMiddleware('pest:edit'), (req, res) => {
  const { id, fieldId, cropId, pestName, name, type, occurDate, severity, treatment, method, effect, dosage, remark } = req.body;
  const data = readData();
  const recordIndex = data.pestRecords.findIndex(p => p.id === id);
  if (recordIndex === -1) {
    return fail(res, '记录不存在');
  }
  const recordPestName = pestName !== undefined ? pestName : (name !== undefined ? name : undefined);
  const recordTreatment = treatment !== undefined ? treatment : (method !== undefined ? method : undefined);
  if (fieldId !== undefined) data.pestRecords[recordIndex].fieldId = parseInt(fieldId);
  if (cropId !== undefined) data.pestRecords[recordIndex].cropId = parseInt(cropId);
  if (recordPestName !== undefined) data.pestRecords[recordIndex].pestName = recordPestName;
  if (type !== undefined) data.pestRecords[recordIndex].type = type;
  if (occurDate !== undefined) data.pestRecords[recordIndex].occurDate = occurDate;
  if (severity !== undefined) data.pestRecords[recordIndex].severity = severity;
  if (recordTreatment !== undefined) data.pestRecords[recordIndex].treatment = recordTreatment;
  if (effect !== undefined) data.pestRecords[recordIndex].effect = effect;
  if (dosage !== undefined) data.pestRecords[recordIndex].dosage = dosage;
  if (remark !== undefined) data.pestRecords[recordIndex].remark = remark;
  writeData(data);
  addOperationLog(req.user.userId, req.user.username, `更新病虫害记录: ${data.pestRecords[recordIndex].pestName}`, '病虫害管理', getClientIp(req));
  success(res, data.pestRecords[recordIndex], '更新成功');
});

// 35. 删除病虫害记录
app.delete('/api/pest/:id', authMiddleware, adminMiddleware, (req, res) => {
  const id = parseInt(req.params.id);
  const data = readData();
  const recordIndex = data.pestRecords.findIndex(p => p.id === id);
  if (recordIndex === -1) {
    return fail(res, '记录不存在');
  }
  const deleted = data.pestRecords.splice(recordIndex, 1)[0];
  writeData(data);
  addOperationLog(req.user.userId, req.user.username, `删除病虫害记录: ${deleted.pestName}`, '病虫害管理', getClientIp(req));
  success(res, null, '删除成功');
});

// 36. 农事作业记录检索（分页+多条件搜索）
app.get('/api/operation/list', authMiddleware, permissionMiddleware('operation:view'), (req, res) => {
  const { current = 1, size = 10, keyword = '', fieldId, cropId, type, operatorId, startDate, endDate } = req.query;
  const data = readData();
  let list = [...data.farmOperations];
  if (keyword) {
    list = list.filter(o => o.content.includes(keyword) || o.type.includes(keyword));
  }
  if (fieldId) {
    list = list.filter(o => o.fieldId === parseInt(fieldId));
  }
  if (cropId) {
    list = list.filter(o => o.cropId === parseInt(cropId));
  }
  if (type) {
    list = list.filter(o => o.type === type);
  }
  if (operatorId) {
    list = list.filter(o => o.operatorId === parseInt(operatorId));
  }
  if (startDate) {
    list = list.filter(o => o.operationDate >= startDate);
  }
  if (endDate) {
    list = list.filter(o => o.operationDate <= endDate);
  }
  list = list.map(o => {
    const field = data.fields.find(f => f.id === o.fieldId);
    const crop = data.crops.find(c => c.id === o.cropId);
    return { ...o, fieldName: field?.fieldName || '', cropName: crop?.cropName || '' };
  });
  list.sort((a, b) => b.id - a.id);
  success(res, paginate(list, current, size));
});

// 37. 作业记录详情
app.get('/api/operation/:id', authMiddleware, permissionMiddleware('operation:view'), (req, res) => {
  const id = parseInt(req.params.id);
  const data = readData();
  const operation = data.farmOperations.find(o => o.id === id);
  if (!operation) {
    return fail(res, '记录不存在');
  }
  const field = data.fields.find(f => f.id === operation.fieldId);
  const crop = data.crops.find(c => c.id === operation.cropId);
  const images = data.farmOperationImages.filter(img => img.operationId === id);
  success(res, { ...operation, fieldName: field?.fieldName || '', cropName: crop?.cropName || '', images });
});

// 38. 获取作业图片附件列表
app.get('/api/operation/images/:operationId', authMiddleware, permissionMiddleware('operation:view'), (req, res) => {
  const operationId = parseInt(req.params.operationId);
  const data = readData();
  const images = data.farmOperationImages.filter(img => img.operationId === operationId);
  success(res, images);
});

// 39. 上传作业图片附件
app.post('/api/operation/image/add', authMiddleware, permissionMiddleware('operation:add'), (req, res) => {
  const { operationId, imageUrl, description } = req.body;
  const data = readData();
  const newImage = {
    id: getNextId(data.farmOperationImages),
    operationId: parseInt(operationId),
    imageUrl: imageUrl || '',
    description: description || '',
    createTime: getCurrentTime()
  };
  data.farmOperationImages.push(newImage);
  writeData(data);
  addOperationLog(req.user.userId, req.user.username, `上传作业图片`, '作业管理', getClientIp(req));
  success(res, newImage, '上传成功');
});

// 39.5 删除作业图片附件
app.delete('/api/operation/image/:id', authMiddleware, adminMiddleware, (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) {
    return fail(res, '无效的图片ID');
  }
  const data = readData();
  const imageIndex = data.farmOperationImages.findIndex(img => img.id === id);
  if (imageIndex === -1) {
    return fail(res, '图片不存在');
  }
  const deleted = data.farmOperationImages.splice(imageIndex, 1)[0];
  writeData(data);
  addOperationLog(req.user.userId, req.user.username, `删除作业图片`, '作业管理', getClientIp(req));
  success(res, null, '删除成功');
});

// ====================== 模块四：农资库存与成本管理 API ======================

// 40. 农资列表（分页+搜索）
app.get('/api/material/list', authMiddleware, permissionMiddleware('material:view'), (req, res) => {
  const { current = 1, size = 10, keyword = '', category } = req.query;
  const data = readData();
  let list = [...data.materials];
  if (keyword) {
    list = list.filter(m => m.materialName.includes(keyword) || m.supplier.includes(keyword));
  }
  if (category) {
    list = list.filter(m => m.category === category);
  }
  list.sort((a, b) => b.id - a.id);
  success(res, paginate(list, current, size));
});

// 41. 新增农资
app.post('/api/material/add', authMiddleware, permissionMiddleware('material:add'), (req, res) => {
  const { materialName, category, unit, specification, stock, safetyStock, price, supplier, remark } = req.body;
  const data = readData();
  const newMaterial = {
    id: getNextId(data.materials),
    materialName,
    category: category || '',
    unit: unit || '',
    specification: specification || '',
    stock: parseFloat(stock) || 0,
    safetyStock: parseFloat(safetyStock) || 0,
    price: parseFloat(price) || 0,
    supplier: supplier || '',
    remark: remark || '',
    createTime: getCurrentTime()
  };
  data.materials.push(newMaterial);
  writeData(data);
  addOperationLog(req.user.userId, req.user.username, `新增农资: ${materialName}`, '农资管理', getClientIp(req));
  success(res, newMaterial, '新增成功');
});

// 42. 更新农资
app.put('/api/material/update', authMiddleware, permissionMiddleware('material:edit'), (req, res) => {
  const { id, materialName, category, unit, specification, stock, safetyStock, price, supplier, remark } = req.body;
  const data = readData();
  const materialIndex = data.materials.findIndex(m => m.id === id);
  if (materialIndex === -1) {
    return fail(res, '农资不存在');
  }
  if (materialName !== undefined) data.materials[materialIndex].materialName = materialName;
  if (category !== undefined) data.materials[materialIndex].category = category;
  if (unit !== undefined) data.materials[materialIndex].unit = unit;
  if (specification !== undefined) data.materials[materialIndex].specification = specification;
  if (stock !== undefined) data.materials[materialIndex].stock = parseFloat(stock);
  if (safetyStock !== undefined) data.materials[materialIndex].safetyStock = parseFloat(safetyStock);
  if (price !== undefined) data.materials[materialIndex].price = parseFloat(price);
  if (supplier !== undefined) data.materials[materialIndex].supplier = supplier;
  if (remark !== undefined) data.materials[materialIndex].remark = remark;
  writeData(data);
  addOperationLog(req.user.userId, req.user.username, `更新农资: ${data.materials[materialIndex].materialName}`, '农资管理', getClientIp(req));
  success(res, data.materials[materialIndex], '更新成功');
});

// 43. 删除农资
app.delete('/api/material/:id', authMiddleware, adminMiddleware, (req, res) => {
  const id = parseInt(req.params.id);
  const data = readData();
  const materialIndex = data.materials.findIndex(m => m.id === id);
  if (materialIndex === -1) {
    return fail(res, '农资不存在');
  }
  const deleted = data.materials.splice(materialIndex, 1)[0];
  writeData(data);
  addOperationLog(req.user.userId, req.user.username, `删除农资: ${deleted.materialName}`, '农资管理', getClientIp(req));
  success(res, null, '删除成功');
});

// 44. 采购入库列表
app.get('/api/material/purchase/list', authMiddleware, permissionMiddleware('material:purchase:view'), (req, res) => {
  const { current = 1, size = 10, keyword = '', materialId, startDate, endDate } = req.query;
  const data = readData();
  let list = [...data.materialPurchases].map(p => {
    const material = data.materials.find(m => m.id === p.materialId);
    return {
      ...p,
      unit: p.unit || (material ? material.unit : ''),
      totalPrice: p.totalPrice !== undefined ? p.totalPrice : p.totalAmount,
      operatorName: p.operatorName || p.operator
    };
  });
  if (keyword) {
    list = list.filter(p => p.materialName.includes(keyword) || p.supplier.includes(keyword));
  }
  if (materialId) {
    list = list.filter(p => p.materialId === parseInt(materialId));
  }
  if (startDate) {
    list = list.filter(p => p.purchaseDate >= startDate);
  }
  if (endDate) {
    list = list.filter(p => p.purchaseDate <= endDate);
  }
  list.sort((a, b) => b.id - a.id);
  success(res, paginate(list, current, size));
});

// 45. 采购入库（自动增加库存）
app.post('/api/material/purchase/add', authMiddleware, permissionMiddleware('material:purchase:add'), (req, res) => {
  const { materialId, quantity, unitPrice, supplier, purchaseDate, remark } = req.body;
  const data = readData();
  const material = data.materials.find(m => m.id === parseInt(materialId));
  if (!material) {
    return fail(res, '农资不存在');
  }
  const qty = parseFloat(quantity) || 0;
  const price = parseFloat(unitPrice) || 0;
  const newPurchase = {
    id: getNextId(data.materialPurchases),
    materialId: parseInt(materialId),
    materialName: material.materialName,
    quantity: qty,
    unit: material.unit,
    unitPrice: price,
    totalPrice: qty * price,
    supplier: supplier || material.supplier,
    purchaseDate: purchaseDate || getCurrentTime().split(' ')[0],
    operatorName: req.user.username,
    operator: req.user.username,
    remark: remark || '',
    createTime: getCurrentTime()
  };
  data.materialPurchases.push(newPurchase);
  material.stock += qty;
  writeData(data);
  addOperationLog(req.user.userId, req.user.username, `采购入库: ${material.materialName} ${qty}${material.unit}`, '农资管理', getClientIp(req));
  success(res, newPurchase, '入库成功');
});

// 46. 领用记录列表
app.get('/api/material/usage/list', authMiddleware, permissionMiddleware('material:usage:view'), (req, res) => {
  const { current = 1, size = 10, keyword = '', materialId, fieldId, startDate, endDate, receiver } = req.query;
  const data = readData();
  let list = [...data.materialUsages];
  if (keyword) {
    list = list.filter(u => u.materialName.includes(keyword) || u.remark.includes(keyword) || (u.purpose && u.purpose.includes(keyword)));
  }
  if (materialId) {
    list = list.filter(u => u.materialId === parseInt(materialId));
  }
  if (fieldId) {
    list = list.filter(u => u.fieldId === parseInt(fieldId));
  }
  if (startDate) {
    list = list.filter(u => u.usageDate >= startDate);
  }
  if (endDate) {
    list = list.filter(u => u.usageDate <= endDate);
  }
  if (receiver) {
    list = list.filter(u => (u.receiverName && u.receiverName.includes(receiver)) || (u.operator && u.operator.includes(receiver)));
  }
  list = list.map(u => {
    const material = data.materials.find(m => m.id === u.materialId);
    const field = data.fields.find(f => f.id === u.fieldId);
    const receiver = u.receiverId ? data.users.find(u2 => u2.id === u.receiverId) : null;
    const operator = u.operatorId ? data.users.find(u2 => u2.id === u.operatorId) : null;
    return {
      ...u,
      unit: u.unit || material?.unit || '',
      fieldName: field?.fieldName || '',
      receiverName: u.receiverName || receiver?.realName || receiver?.username || '',
      operatorName: u.operatorName || operator?.realName || operator?.username || u.operator || '',
      purpose: u.purpose || u.remark || ''
    };
  });
  list.sort((a, b) => b.id - a.id);
  success(res, paginate(list, current, size));
});

// 47. 农资领用（自动减少库存）
app.post('/api/material/usage/add', authMiddleware, permissionMiddleware('material:usage:add'), (req, res) => {
  const { materialId, quantity, fieldId, usageDate, remark, receiverId, receiverName, purpose } = req.body;
  const data = readData();
  const material = data.materials.find(m => m.id === parseInt(materialId));
  if (!material) {
    return fail(res, '农资不存在');
  }
  const qty = parseFloat(quantity) || 0;
  if (material.stock < qty) {
    return fail(res, '库存不足');
  }
  const receiver = receiverId ? data.users.find(u => u.id === parseInt(receiverId)) : null;
  const operator = data.users.find(u => u.id === req.user.userId);
  const newUsage = {
    id: getNextId(data.materialUsages),
    materialId: parseInt(materialId),
    materialName: material.materialName,
    unit: material.unit || '',
    quantity: qty,
    fieldId: parseInt(fieldId) || 0,
    usageDate: usageDate || getCurrentTime().split(' ')[0],
    receiverId: parseInt(receiverId) || 0,
    receiverName: receiverName || receiver?.realName || receiver?.username || '',
    operatorId: req.user.userId,
    operator: operator?.realName || operator?.username || req.user.username,
    operatorName: operator?.realName || operator?.username || req.user.username,
    purpose: purpose || remark || '',
    remark: remark || '',
    createTime: getCurrentTime()
  };
  data.materialUsages.push(newUsage);
  material.stock -= qty;
  writeData(data);
  addOperationLog(req.user.userId, req.user.username, `农资领用: ${material.materialName} ${qty}${material.unit}`, '农资管理', getClientIp(req));
  success(res, newUsage, '领用成功');
});

// 48. 库存预警列表（低于安全库存）
app.get('/api/material/warning', authMiddleware, permissionMiddleware('material:warning:view'), (req, res) => {
  const data = readData();
  const list = data.materials
    .filter(m => m.stock < m.safetyStock)
    .map(m => ({
      ...m,
      name: m.materialName,
      materialName: m.materialName,
      category: m.type,
      type: m.type,
      currentStock: m.stock,
      stock: m.stock,
      safeStock: m.safetyStock,
      safetyStock: m.safetyStock
    }));
  success(res, list);
});

// 49. 消耗统计（按类别汇总）
app.get('/api/material/consumption/stats', authMiddleware, permissionMiddleware('material:warning:view'), (req, res) => {
  const { startDate, endDate, category } = req.query;
  const data = readData();
  let usages = [...data.materialUsages];
  if (startDate) {
    usages = usages.filter(u => u.usageDate >= startDate);
  }
  if (endDate) {
    usages = usages.filter(u => u.usageDate <= endDate);
  }
  const categoryStats = {};
  usages.forEach(u => {
    const material = data.materials.find(m => m.id === u.materialId);
    if (material) {
      const cat = material.category || '其他';
      if (category && cat !== category) return;
      if (!categoryStats[cat]) {
        categoryStats[cat] = {
          category: cat,
          type: cat,
          quantity: 0,
          totalQuantity: 0,
          totalCost: 0
        };
      }
      categoryStats[cat].quantity += u.quantity;
      categoryStats[cat].totalQuantity += u.quantity;
      categoryStats[cat].totalCost += u.quantity * (material.price || 0);
    }
  });
  const result = Object.values(categoryStats);
  success(res, result);
});

// ====================== 模块五：用工、采收与产销台账 API ======================

// 50. 用工工时列表（分页+搜索）
app.get('/api/labor/list', authMiddleware, permissionMiddleware('labor:view'), (req, res) => {
  const { current = 1, size = 10, keyword = '', workType, fieldId, startDate, endDate } = req.query;
  const data = readData();
  let list = [...data.laborRecords];
  if (keyword) {
    list = list.filter(l => l.workerName.includes(keyword) || l.remark.includes(keyword));
  }
  if (workType) {
    list = list.filter(l => l.workType === workType);
  }
  if (fieldId) {
    list = list.filter(l => l.fieldId === parseInt(fieldId));
  }
  if (startDate) {
    list = list.filter(l => l.workDate >= startDate);
  }
  if (endDate) {
    list = list.filter(l => l.workDate <= endDate);
  }
  list = list.map(l => {
    const field = data.fields.find(f => f.id === l.fieldId);
    return { ...l, fieldName: field?.fieldName || '' };
  });
  list.sort((a, b) => b.id - a.id);
  success(res, paginate(list, current, size));
});

// 51. 登记用工工时
app.post('/api/labor/add', authMiddleware, permissionMiddleware('labor:add'), (req, res) => {
  const { workerName, workType, fieldId, workDate, workHours, hourlyWage, remark } = req.body;
  const data = readData();
  const hours = parseFloat(workHours) || 0;
  const wage = parseFloat(hourlyWage) || 0;
  const newRecord = {
    id: getNextId(data.laborRecords),
    workerName,
    workType: workType || '',
    fieldId: parseInt(fieldId) || 0,
    workDate: workDate || getCurrentTime().split(' ')[0],
    workHours: hours,
    hourlyWage: wage,
    totalWage: hours * wage,
    remark: remark || '',
    createTime: getCurrentTime()
  };
  data.laborRecords.push(newRecord);
  writeData(data);
  addOperationLog(req.user.userId, req.user.username, '登记用工: ' + workerName, '用工管理', getClientIp(req));
  success(res, newRecord, '登记成功');
});

// 52. 更新用工记录
app.put('/api/labor/update', authMiddleware, permissionMiddleware('labor:edit'), (req, res) => {
  const { id, workerName, workType, fieldId, workDate, workHours, hourlyWage, remark } = req.body;
  const data = readData();
  const recordIndex = data.laborRecords.findIndex(l => l.id === id);
  if (recordIndex === -1) {
    return fail(res, '记录不存在');
  }
  if (workerName !== undefined) data.laborRecords[recordIndex].workerName = workerName;
  if (workType !== undefined) data.laborRecords[recordIndex].workType = workType;
  if (fieldId !== undefined) data.laborRecords[recordIndex].fieldId = parseInt(fieldId);
  if (workDate !== undefined) data.laborRecords[recordIndex].workDate = workDate;
  if (workHours !== undefined) data.laborRecords[recordIndex].workHours = parseFloat(workHours);
  if (hourlyWage !== undefined) data.laborRecords[recordIndex].hourlyWage = parseFloat(hourlyWage);
  if (workHours !== undefined || hourlyWage !== undefined) {
    data.laborRecords[recordIndex].totalWage = data.laborRecords[recordIndex].workHours * data.laborRecords[recordIndex].hourlyWage;
  }
  if (remark !== undefined) data.laborRecords[recordIndex].remark = remark;
  writeData(data);
  addOperationLog(req.user.userId, req.user.username, '更新用工记录', '用工管理', getClientIp(req));
  success(res, data.laborRecords[recordIndex], '更新成功');
});

// 53. 删除用工记录
app.delete('/api/labor/:id', authMiddleware, adminMiddleware, (req, res) => {
  const id = parseInt(req.params.id);
  const data = readData();
  const recordIndex = data.laborRecords.findIndex(l => l.id === id);
  if (recordIndex === -1) {
    return fail(res, '记录不存在');
  }
  const deleted = data.laborRecords.splice(recordIndex, 1)[0];
  writeData(data);
  addOperationLog(req.user.userId, req.user.username, '删除用工记录: ' + deleted.workerName, '用工管理', getClientIp(req));
  success(res, null, '删除成功');
});

// 54. 采收产量列表（分页+搜索，按地块/作物筛选）
app.get('/api/harvest/list', authMiddleware, permissionMiddleware('harvest:view'), (req, res) => {
  const { current = 1, size = 10, keyword = '', fieldId, cropId, startDate, endDate } = req.query;
  const data = readData();
  let list = [...data.harvestRecords];
  if (keyword) {
    list = list.filter(h => h.remark.includes(keyword));
  }
  if (fieldId) {
    list = list.filter(h => h.fieldId === parseInt(fieldId));
  }
  if (cropId) {
    list = list.filter(h => h.cropId === parseInt(cropId));
  }
  if (startDate) {
    list = list.filter(h => h.harvestDate >= startDate);
  }
  if (endDate) {
    list = list.filter(h => h.harvestDate <= endDate);
  }
  list = list.map(h => {
    const field = data.fields.find(f => f.id === h.fieldId);
    const crop = data.crops.find(c => c.id === h.cropId);
    return { ...h, fieldName: field?.fieldName || '', cropName: crop?.cropName || '' };
  });
  list.sort((a, b) => b.id - a.id);
  success(res, paginate(list, current, size));
});

// 55. 录入采收产量
app.post('/api/harvest/add', authMiddleware, permissionMiddleware('harvest:add'), (req, res) => {
  const { fieldId, cropId, harvestDate, quantity, unit, unitPrice, qualityGrade, operator, remark } = req.body;
  const data = readData();
  const qty = parseFloat(quantity) || 0;
  const price = parseFloat(unitPrice) || 0;
  const newRecord = {
    id: getNextId(data.harvestRecords),
    fieldId: parseInt(fieldId) || 0,
    cropId: parseInt(cropId) || 0,
    harvestDate: harvestDate || getCurrentTime().split(' ')[0],
    quantity: qty,
    unit: unit || '公斤',
    unitPrice: price,
    totalValue: qty * price,
    qualityGrade: qualityGrade || '一级',
    operator: operator || req.user.username,
    remark: remark || '',
    createTime: getCurrentTime()
  };
  data.harvestRecords.push(newRecord);
  writeData(data);
  addOperationLog(req.user.userId, req.user.username, '录入采收产量', '采收管理', getClientIp(req));
  success(res, newRecord, '录入成功');
});

// 56. 更新采收记录
app.put('/api/harvest/update', authMiddleware, permissionMiddleware('harvest:edit'), (req, res) => {
  const { id, fieldId, cropId, harvestDate, quantity, unit, unitPrice, qualityGrade, operator, remark } = req.body;
  const data = readData();
  const recordIndex = data.harvestRecords.findIndex(h => h.id === id);
  if (recordIndex === -1) {
    return fail(res, '记录不存在');
  }
  if (fieldId !== undefined) data.harvestRecords[recordIndex].fieldId = parseInt(fieldId);
  if (cropId !== undefined) data.harvestRecords[recordIndex].cropId = parseInt(cropId);
  if (harvestDate !== undefined) data.harvestRecords[recordIndex].harvestDate = harvestDate;
  if (quantity !== undefined) data.harvestRecords[recordIndex].quantity = parseFloat(quantity);
  if (unit !== undefined) data.harvestRecords[recordIndex].unit = unit;
  if (unitPrice !== undefined) data.harvestRecords[recordIndex].unitPrice = parseFloat(unitPrice);
  if (quantity !== undefined || unitPrice !== undefined) {
    data.harvestRecords[recordIndex].totalValue = data.harvestRecords[recordIndex].quantity * data.harvestRecords[recordIndex].unitPrice;
  }
  if (qualityGrade !== undefined) data.harvestRecords[recordIndex].qualityGrade = qualityGrade;
  if (operator !== undefined) data.harvestRecords[recordIndex].operator = operator;
  if (remark !== undefined) data.harvestRecords[recordIndex].remark = remark;
  writeData(data);
  addOperationLog(req.user.userId, req.user.username, '更新采收记录', '采收管理', getClientIp(req));
  success(res, data.harvestRecords[recordIndex], '更新成功');
});

// 57. 删除采收记录
app.delete('/api/harvest/:id', authMiddleware, adminMiddleware, (req, res) => {
  const id = parseInt(req.params.id);
  const data = readData();
  const recordIndex = data.harvestRecords.findIndex(h => h.id === id);
  if (recordIndex === -1) {
    return fail(res, '记录不存在');
  }
  data.harvestRecords.splice(recordIndex, 1);
  writeData(data);
  addOperationLog(req.user.userId, req.user.username, '删除采收记录', '采收管理', getClientIp(req));
  success(res, null, '删除成功');
});

// 58. 销售记录列表（分页+搜索）
app.get('/api/sales/list', authMiddleware, permissionMiddleware('sales:view'), (req, res) => {
  const { current = 1, size = 10, keyword = '', cropId, customer, startDate, endDate } = req.query;
  const data = readData();
  let list = [...data.salesRecords];
  if (keyword) {
    list = list.filter(s => s.saleNo.includes(keyword) || s.customer.includes(keyword) || (s.cropName && s.cropName.includes(keyword)));
  }
  if (cropId) {
    list = list.filter(s => s.cropId === parseInt(cropId));
  }
  if (customer) {
    list = list.filter(s => s.customer.includes(customer));
  }
  if (startDate) {
    list = list.filter(s => s.saleDate >= startDate);
  }
  if (endDate) {
    list = list.filter(s => s.saleDate <= endDate);
  }
  list.sort((a, b) => b.id - a.id);
  success(res, paginate(list, current, size));
});

function generateSaleNo() {
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const data = readData();
  const count = data.salesRecords.filter(s => {
    const d = new Date(s.createTime);
    return d.getFullYear() === year && d.getMonth() + 1 === now.getMonth() + 1;
  }).length + 1;
  return 'S' + year + month + String(count).padStart(3, '0');
}

// 59. 新增销售记录
app.post('/api/sales/add', authMiddleware, permissionMiddleware('sales:add'), (req, res) => {
  const { cropId, cropName, quantity, unit, unitPrice, customer, saleDate, remark } = req.body;
  const data = readData();
  const qty = parseFloat(quantity) || 0;
  const price = parseFloat(unitPrice) || 0;
  const newRecord = {
    id: getNextId(data.salesRecords),
    saleNo: generateSaleNo(),
    cropId: parseInt(cropId) || 0,
    cropName: cropName || '',
    quantity: qty,
    unit: unit || '公斤',
    unitPrice: price,
    totalAmount: qty * price,
    customer: customer || '',
    saleDate: saleDate || getCurrentTime().split(' ')[0],
    remark: remark || '',
    createTime: getCurrentTime()
  };
  data.salesRecords.push(newRecord);
  writeData(data);
  addOperationLog(req.user.userId, req.user.username, '新增销售记录', '销售管理', getClientIp(req));
  success(res, newRecord, '新增成功');
});

// 60. 更新销售记录
app.put('/api/sales/update', authMiddleware, permissionMiddleware('sales:edit'), (req, res) => {
  const { id, cropId, cropName, quantity, unit, unitPrice, customer, saleDate, remark } = req.body;
  const data = readData();
  const recordIndex = data.salesRecords.findIndex(s => s.id === id);
  if (recordIndex === -1) {
    return fail(res, '记录不存在');
  }
  if (cropId !== undefined) data.salesRecords[recordIndex].cropId = parseInt(cropId);
  if (cropName !== undefined) data.salesRecords[recordIndex].cropName = cropName;
  if (quantity !== undefined) data.salesRecords[recordIndex].quantity = parseFloat(quantity);
  if (unit !== undefined) data.salesRecords[recordIndex].unit = unit;
  if (unitPrice !== undefined) data.salesRecords[recordIndex].unitPrice = parseFloat(unitPrice);
  if (quantity !== undefined || unitPrice !== undefined) {
    data.salesRecords[recordIndex].totalAmount = data.salesRecords[recordIndex].quantity * data.salesRecords[recordIndex].unitPrice;
  }
  if (customer !== undefined) data.salesRecords[recordIndex].customer = customer;
  if (saleDate !== undefined) data.salesRecords[recordIndex].saleDate = saleDate;
  if (remark !== undefined) data.salesRecords[recordIndex].remark = remark;
  writeData(data);
  addOperationLog(req.user.userId, req.user.username, '更新销售记录', '销售管理', getClientIp(req));
  success(res, data.salesRecords[recordIndex], '更新成功');
});

// 61. 删除销售记录
app.delete('/api/sales/:id', authMiddleware, adminMiddleware, (req, res) => {
  const id = parseInt(req.params.id);
  const data = readData();
  const recordIndex = data.salesRecords.findIndex(s => s.id === id);
  if (recordIndex === -1) {
    return fail(res, '记录不存在');
  }
  const deleted = data.salesRecords.splice(recordIndex, 1)[0];
  writeData(data);
  addOperationLog(req.user.userId, req.user.username, '删除销售记录: ' + deleted.saleNo, '销售管理', getClientIp(req));
  success(res, null, '删除成功');
});

// 62. 成本利润核算列表（按地块动态计算）
app.get('/api/costprofit/list', authMiddleware, permissionMiddleware('costprofit:view'), (req, res) => {
  const data = readData();
  const fields = data.fields || [];
  const materials = data.materials || [];
  const materialUsages = data.materialUsages || [];
  const laborRecords = data.laborRecords || [];
  const harvestRecords = data.harvestRecords || [];
  const plantingRecords = data.plantingRecords || [];
  const crops = data.crops || [];

  const fieldCostProfit = fields.map(field => {
    const fieldId = field.id;

    const materialCost = materialUsages
      .filter(u => u.fieldId === fieldId)
      .reduce((sum, u) => {
        const material = materials.find(m => m.id === u.materialId);
        return sum + (u.quantity || 0) * (material ? (material.price || 0) : 0);
      }, 0);

    const laborCost = laborRecords
      .filter(l => l.fieldId === fieldId)
      .reduce((sum, l) => sum + (l.totalWage || 0), 0);

    const otherCost = 0;

    const totalCost = materialCost + laborCost + otherCost;

    const income = harvestRecords
      .filter(h => h.fieldId === fieldId)
      .reduce((sum, h) => sum + (h.totalValue || 0), 0);

    const profit = income - totalCost;

    const profitRate = totalCost > 0 ? ((profit / totalCost) * 100).toFixed(2) : '0.00';

    const plantings = plantingRecords.filter(p => p.fieldId === fieldId);
    const cropNames = plantings.map(p => {
      const crop = crops.find(c => c.id === p.cropId);
      return crop ? crop.cropName : '';
    }).filter(n => n).join('、') || '暂无';

    return {
      id: fieldId,
      fieldName: field.fieldName,
      cropName: cropNames,
      materialCost: Number(materialCost.toFixed(2)),
      laborCost: Number(laborCost.toFixed(2)),
      otherCost: Number(otherCost.toFixed(2)),
      totalCost: Number(totalCost.toFixed(2)),
      income: Number(income.toFixed(2)),
      profit: Number(profit.toFixed(2)),
      profitRate: profitRate
    };
  });

  success(res, fieldCostProfit);
});

// 63. 成本利润汇总统计
app.get('/api/costprofit/summary', authMiddleware, permissionMiddleware('costprofit:view'), (req, res) => {
  const data = readData();
  const fields = data.fields || [];
  const materials = data.materials || [];
  const materialUsages = data.materialUsages || [];
  const laborRecords = data.laborRecords || [];
  const harvestRecords = data.harvestRecords || [];

  let totalCost = 0;
  let totalIncome = 0;

  fields.forEach(field => {
    const fieldId = field.id;

    const materialCost = materialUsages
      .filter(u => u.fieldId === fieldId)
      .reduce((sum, u) => {
        const material = materials.find(m => m.id === u.materialId);
        return sum + (u.quantity || 0) * (material ? (material.price || 0) : 0);
      }, 0);

    const laborCost = laborRecords
      .filter(l => l.fieldId === fieldId)
      .reduce((sum, l) => sum + (l.totalWage || 0), 0);

    const income = harvestRecords
      .filter(h => h.fieldId === fieldId)
      .reduce((sum, h) => sum + (h.totalValue || 0), 0);

    totalCost += materialCost + laborCost;
    totalIncome += income;
  });

  const netProfit = totalIncome - totalCost;
  const profitRate = totalCost > 0 ? ((netProfit / totalCost) * 100).toFixed(2) : '0.00';

  success(res, {
    totalCost: Number(totalCost.toFixed(2)),
    totalIncome: Number(totalIncome.toFixed(2)),
    netProfit: Number(netProfit.toFixed(2)),
    profitRate: profitRate
  });
});

// ====================== 模块六：数据可视化与报表 API ======================

// 64. 综合数据大屏概览
app.get('/api/dashboard/summary', authMiddleware, permissionMiddleware('dashboard:view'), (req, res) => {
  const data = readData();
  const fieldCount = data.fields.length;
  const cropCount = data.crops.length;
  const totalFieldArea = data.fields.reduce((sum, f) => sum + f.area, 0);
  const plantingArea = data.plantingRecords.filter(p => p.status === 'growing').reduce((sum, p) => sum + p.area, 0);
  const totalHarvest = data.harvestRecords.reduce((sum, h) => sum + h.quantity, 0);
  const totalOutput = data.harvestRecords.reduce((sum, h) => sum + h.totalValue, 0);
  const totalSales = data.salesRecords.reduce((sum, s) => sum + s.totalAmount, 0);
  const pendingOrders = data.workOrders.filter(w => w.status === 'pending').length;
  const processingOrders = data.workOrders.filter(w => w.status === 'processing').length;
  const completedOrders = data.workOrders.filter(w => w.status === 'completed').length;
  const materialCount = data.materials.length;
  const warningCount = data.materials.filter(m => m.stock < m.safetyStock).length;
  const userCount = data.users.filter(u => u.status === 1).length;

  success(res, {
    totalFields: fieldCount,
    totalCrops: cropCount,
    totalArea: totalFieldArea,
    plantingArea,
    totalYield: totalHarvest,
    totalValue: totalOutput,
    totalSales,
    totalMaterialUsed: data.materialUsages.reduce((sum, u) => sum + u.quantity, 0),
    totalLabor: data.laborRecords.reduce((sum, l) => sum + (l.workHours || 0), 0),
    pendingOrders,
    processingOrders,
    completedOrders,
    materialCount,
    warningCount,
    userCount
  });
});

// 65. 种植统计图表数据
app.get('/api/dashboard/planting-stats', authMiddleware, permissionMiddleware('dashboard:view'), (req, res) => {
  const data = readData();
  const cropStats = {};
  data.plantingRecords.forEach(p => {
    const crop = data.crops.find(c => c.id === p.cropId);
    const cropName = crop ? crop.cropName : '未知';
    if (!cropStats[cropName]) {
      cropStats[cropName] = { cropName, area: 0, count: 0 };
    }
    cropStats[cropName].area += p.area;
    cropStats[cropName].count += 1;
  });
  const list = Object.values(cropStats);

  const statusStats = {
    growing: data.plantingRecords.filter(p => p.status === 'growing').length,
    harvested: data.plantingRecords.filter(p => p.status === 'harvested').length
  };

  success(res, { byCrop: list, byStatus: statusStats, totalFields: data.fields.length, totalCrops: data.crops.length });
});

// 66. 采收统计图表数据
app.get('/api/dashboard/harvest-stats', authMiddleware, permissionMiddleware('dashboard:view'), (req, res) => {
  const data = readData();
  const monthlyStats = {};
  data.harvestRecords.forEach(h => {
    const month = h.harvestDate.substring(0, 7);
    if (!monthlyStats[month]) {
      monthlyStats[month] = { month, quantity: 0, value: 0 };
    }
    monthlyStats[month].quantity += h.quantity;
    monthlyStats[month].value += h.totalValue;
  });
  const list = Object.values(monthlyStats).sort((a, b) => a.month.localeCompare(b.month));

  const cropStats = {};
  data.harvestRecords.forEach(h => {
    const crop = data.crops.find(c => c.id === h.cropId);
    const cropName = crop ? crop.cropName : '未知';
    if (!cropStats[cropName]) {
      cropStats[cropName] = { cropName, quantity: 0, value: 0 };
    }
    cropStats[cropName].quantity += h.quantity;
    cropStats[cropName].value += h.totalValue;
  });
  const byCrop = Object.values(cropStats);

  success(res, { byMonth: list, byCrop });
});

// 67. 农资消耗统计图表数据
app.get('/api/dashboard/material-stats', authMiddleware, permissionMiddleware('dashboard:view'), (req, res) => {
  const data = readData();
  const categoryStats = {};
  data.materialUsages.forEach(u => {
    const material = data.materials.find(m => m.id === u.materialId);
    const category = material ? material.category : '其他';
    if (!categoryStats[category]) {
      categoryStats[category] = { category, count: 0, totalCost: 0 };
    }
    categoryStats[category].count += u.quantity;
    categoryStats[category].totalCost += u.quantity * (material ? material.price : 0);
  });
  const byCategory = Object.values(categoryStats);

  const monthlyStats = {};
  data.materialUsages.forEach(u => {
    const month = u.usageDate.substring(0, 7);
    const material = data.materials.find(m => m.id === u.materialId);
    if (!monthlyStats[month]) {
      monthlyStats[month] = { month, totalCost: 0 };
    }
    monthlyStats[month].totalCost += u.quantity * (material ? material.price : 0);
  });
  const byMonth = Object.values(monthlyStats).sort((a, b) => a.month.localeCompare(b.month));

  success(res, { byCategory, byMonth, totalMaterials: data.materials.length });
});

// 68. 用工统计图表数据
app.get('/api/dashboard/labor-stats', authMiddleware, permissionMiddleware('dashboard:view'), (req, res) => {
  const data = readData();
  const typeStats = {};
  data.laborRecords.forEach(l => {
    if (!typeStats[l.workType]) {
      typeStats[l.workType] = { workType: l.workType, totalHours: 0, totalWage: 0, count: 0 };
    }
    typeStats[l.workType].totalHours += l.workHours;
    typeStats[l.workType].totalWage += l.totalWage;
    typeStats[l.workType].count += 1;
  });
  const byType = Object.values(typeStats);

  const monthlyStats = {};
  data.laborRecords.forEach(l => {
    const month = l.workDate.substring(0, 7);
    if (!monthlyStats[month]) {
      monthlyStats[month] = { month, totalHours: 0, totalWage: 0 };
    }
    monthlyStats[month].totalHours += l.workHours;
    monthlyStats[month].totalWage += l.totalWage;
  });
  const byMonth = Object.values(monthlyStats).sort((a, b) => a.month.localeCompare(b.month));

  success(res, { byType, byMonth, totalWorkorders: data.workOrders.length });
});

function toCSV(headers, rows) {
  const headerRow = headers.map(h => '"' + h + '"').join(',');
  const dataRows = rows.map(row =>
    headers.map((h, i) => {
      let val = row[i] !== undefined && row[i] !== null ? String(row[i]) : '';
      val = val.replace(/"/g, '""');
      return '"' + val + '"';
    }).join(',')
  );
  return '\uFEFF' + [headerRow, ...dataRows].join('\n');
}

// 69. 工单导出CSV
app.get('/api/export/workorders', authMiddleware, permissionMiddleware('dashboard:view'), (req, res) => {
  const data = readData();
  const headers = ['工单编号', '标题', '类型', '地块', '作物', '指派人', '状态', '优先级', '计划时间', '创建时间'];
  const rows = data.workOrders.map(w => {
    const field = data.fields.find(f => f.id === w.fieldId);
    const crop = data.crops.find(c => c.id === w.cropId);
    const statusMap = { pending: '待办', processing: '进行中', completed: '已完成' };
    const priorityMap = { high: '高', medium: '中', low: '低' };
    return [
      w.orderNo, w.title, w.type, field ? field.fieldName : '', crop ? crop.cropName : '',
      w.assigneeName, statusMap[w.status] || w.status, priorityMap[w.priority] || w.priority,
      w.planTime, w.createTime
    ];
  });
  const csv = toCSV(headers, rows);
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename=workorders.csv');
  res.send(csv);
});

// 70. 农事作业导出CSV
app.get('/api/export/operations', authMiddleware, permissionMiddleware('dashboard:view'), (req, res) => {
  const data = readData();
  const headers = ['作业类型', '地块', '作物', '操作人', '作业时间', '工时', '内容', '天气', '温度'];
  const rows = data.farmOperations.map(o => {
    const field = data.fields.find(f => f.id === o.fieldId);
    const crop = data.crops.find(c => c.id === o.cropId);
    return [
      o.type, field ? field.fieldName : '', crop ? crop.cropName : '', o.operatorName,
      o.operationDate, o.workHours, o.content, o.weather, o.temperature
    ];
  });
  const csv = toCSV(headers, rows);
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename=operations.csv');
  res.send(csv);
});

// 71. 采收记录导出CSV
app.get('/api/export/harvest', authMiddleware, permissionMiddleware('dashboard:view'), (req, res) => {
  const data = readData();
  const headers = ['采收日期', '地块', '作物', '数量', '单位', '单价', '总值', '等级', '操作人', '备注'];
  const rows = data.harvestRecords.map(h => {
    const field = data.fields.find(f => f.id === h.fieldId);
    const crop = data.crops.find(c => c.id === h.cropId);
    return [
      h.harvestDate, field ? field.fieldName : '', crop ? crop.cropName : '', h.quantity,
      h.unit, h.unitPrice, h.totalValue, h.qualityGrade, h.operator, h.remark
    ];
  });
  const csv = toCSV(headers, rows);
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename=harvest.csv');
  res.send(csv);
});

// 72. 销售记录导出CSV
app.get('/api/export/sales', authMiddleware, permissionMiddleware('dashboard:view'), (req, res) => {
  const data = readData();
  const headers = ['销售单号', '作物', '数量', '单价', '总金额', '客户', '销售日期', '备注'];
  const rows = data.salesRecords.map(s => [
    s.saleNo, s.cropName, s.quantity, s.unitPrice, s.totalAmount,
    s.customer, s.saleDate, s.remark
  ]);
  const csv = toCSV(headers, rows);
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename=sales.csv');
  res.send(csv);
});

// ====================== 启动服务 ======================

app.listen(PORT, () => {
  console.log('智慧农田管理系统后端服务已启动');
  console.log('服务地址: http://localhost:' + PORT);
  console.log('API文档: 共72个接口');
});
