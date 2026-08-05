// 数据迁移脚本：本地 → Render 服务器
const fs = require('fs');
const path = require('path');

const REMOTE = 'https://kane-workbench.onrender.com';
const DATA_DIR = path.join(__dirname, 'data');
const USERDATA_DIR = path.join(DATA_DIR, 'userdata');

async function migrate() {
  // 读取参数
  const username = process.argv[2] || 'kane';
  const password = process.argv[3];

  if (!password) {
    console.log('用法: node migrate.js <用户名> <密码>');
    console.log('示例: node migrate.js kane mypassword');
    process.exit(1);
  }

  console.log(`迁移目标: ${REMOTE}`);
  console.log(`用户名: ${username}`);
  console.log('---');

  // 读本地数据
  const usersPath = path.join(DATA_DIR, 'users.json');
  const userdataPath = path.join(USERDATA_DIR, `${username}.json`);

  if (!fs.existsSync(userdataPath)) {
    console.error(`未找到用户数据: ${userdataPath}`);
    process.exit(1);
  }

  const userData = JSON.parse(fs.readFileSync(userdataPath, 'utf-8'));
  console.log(`本地数据: ${JSON.stringify(userData)}`);

  // Step 1: 尝试注册
  console.log('\n[1/3] 注册账号...');
  let token;

  const registerResp = await fetch(`${REMOTE}/api/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  const registerResult = await registerResp.json();
  console.log(`  注册: ${registerResp.status} ${registerResult.error || registerResult.success || ''}`);

  // Step 2: 登录
  console.log('\n[2/3] 登录获取 token...');
  const loginResp = await fetch(`${REMOTE}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  const loginResult = await loginResp.json();

  if (!loginResult.token) {
    console.error(`  登录失败: ${JSON.stringify(loginResult)}`);
    process.exit(1);
  }
  token = loginResult.token;
  console.log(`  登录成功, token: ${token.substring(0, 20)}...`);

  // Step 3: 推送数据
  console.log('\n[3/3] 推送数据...');
  const dataResp = await fetch(`${REMOTE}/api/data`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
    },
    body: JSON.stringify({ data: userData }),
  });
  const dataResult = await dataResp.json();
  console.log(`  推送: ${dataResp.status} ${JSON.stringify(dataResult)}`);

  console.log('\n迁移完成!');
}

migrate().catch(err => {
  console.error('迁移失败:', err.message);
  process.exit(1);
});
