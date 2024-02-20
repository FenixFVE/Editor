
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('loginBtn').addEventListener('click', () => {
        showModal('loginModal')
    });
    document.getElementById('registerBtn').addEventListener('click', () => {
        showModal('registerModal')
    });
    document.getElementById('closeLogin').addEventListener('click', () => {
        closeModal('loginModal')
    });
    document.getElementById('closeRegister').addEventListener('click', () => {
        closeModal('registerModal')
    });
    document.getElementById('closeMassage').addEventListener('click', () => {
        closeMessageModal()
    });

    document.getElementById('loginButton').addEventListener('click', async () => {
        await login();
        await initializeAndLoadEditor();
    });
    document.getElementById('registerButton').addEventListener('click', async () => {
        await register();
    });
    document.getElementById('logoutBtn').addEventListener('click', async () => {
        await logout();
        await initializeAndLoadEditor();
    });
    document.getElementById('deleteUserBtn').addEventListener('click', async () => {
        await deleteUser();
        await initializeAndLoadEditor();
    });
    document.getElementById('saveBtn').addEventListener('click', async () => {
        await saveText();
    });
});

document.addEventListener('DOMContentLoaded', async () => {
    await initializeAndLoadEditor();
    await checkLoginStatus();
});

function showModal(modalId) {
    document.getElementById(modalId).style.display = 'block';
}
function closeModal(modalId) {
    document.getElementById(modalId).style.display = 'none';
    //document.getElementById(modalId + 'Error').innerText = '';
}
function closeMessageModal() {
    document.getElementById('messageModal').style.display = 'none';
}
function showMessage(message) {
    document.getElementById('messageText').innerText = message;
    document.getElementById('messageModal').style.display = 'block';
}
function displayError(modalId, message) {
    document.getElementById(modalId).innerText = message;
}

async function checkLoginStatus() {
    try {
        const response = await fetch('/check');
        const data = await response.json();
        if (data.loggedin) {
            document.getElementById('userInfo').innerText = 'Logged in as ' + data.username;
            document.getElementById('userInfo').style.display = 'block';
            document.getElementById('logoutBtn').style.display = 'inline';
            document.getElementById('deleteUserBtn').style.display = 'inline';
            document.getElementById('loginBtn').style.display = 'none';
            document.getElementById('registerBtn').style.display = 'none';
        } else {
            //document.getElementById('userInfo').style.display = 'none';
            document.getElementById('userInfo').innerText = 'Please Login'
            document.getElementById('userInfo').style.display = 'block';
            document.getElementById('logoutBtn').style.display = 'none';
            document.getElementById('deleteUserBtn').style.display = 'none';
            document.getElementById('loginBtn').style.display = 'inline';
            document.getElementById('registerBtn').style.display = 'inline';
        }
    } catch (error) {
        console.error('Error:', error);
    }
}

async function login() {
    const username = document.getElementById('loginUsername').value;
    const password = document.getElementById('loginPassword').value;
    try {
        const response = await fetch('/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password }),
        });
        const data = await response.json();
        if (data.error) {
            displayError('loginError', data.error);
        } else {
            await checkLoginStatus();
            closeModal('loginModal');
        }
    } catch (error) {
        console.error('Error:', error);
    }
}

async function register() {
    const username = document.getElementById('registerUsername').value;
    const password = document.getElementById('registerPassword').value;
    try {
        const response = await fetch('/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password }),
        });
        const data = await response.json();
        if (data.error) {
            displayError('registerError', data.error);
        } else {
            showMessage('User registered successfully! Please log in.');
            closeModal('registerModal');
            document.getElementById('registerUsername').value = '';
            document.getElementById('registerPassword').value = '';
        }
    } catch (error) {
        console.error('Error:', error);
    }
}

async function logout() {
    try {
        const response = await fetch('/logout', {
            method: 'POST',
        });
        await response.json();
        await checkLoginStatus();
    } catch (error) {
        console.error('Error:', error);
    }
}

async function deleteUser() {
    try {
        const response = await fetch('/deleteuser', {
            method: 'POST', 
        });
        const data = await response.json();
        showMessage(data.message);
        await checkLoginStatus();
    } catch (error) {
        console.error('Error:', error);
    }
}

async function saveText() {
  const text = editor.getValue(); // Get text from editor
  try {
    const response = await fetch('/save', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ text }),
    });
    const data = await response.text(); // Assuming the server response is plain text
    showMessage(data);
  } catch (error) {
    console.error('Error:', error);
  }
}
  
async function initializeAndLoadEditor() {
  try {
    const response = await fetch('/load');
    const data = await response.text();
    if (window.editor) {
      window.editor.setValue(data);
    } else {
      window.editor = CodeMirror(document.getElementById('notepad'), {
        value: data,
        mode: "python",
        theme: "monokai",
        lineNumbers: true,
        lineWrapping: true,
      });
    }
  } catch (error) {
    console.error('Error initializing editor or loading content:', error);
    if (!window.editor) {
      window.editor = CodeMirror(document.getElementById('notepad'), {
        value: "",
        mode: "python",
        theme: "monokai",
        lineNumbers: true,
        lineWrapping: true,
      });
    }
  }
}