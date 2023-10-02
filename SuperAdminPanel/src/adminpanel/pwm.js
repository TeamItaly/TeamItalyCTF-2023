//we have to simulate the browser password manager :(
//i really wanted to use the real password manager but it was just so inconsistent and hard to work with
const PASSWORD = process.env.PASSWORD || 'fake_password';

export let __trigger_browser_password_manager = [
    {type: "request", url: "javascript:if(window.location.host!==\"127.0.0.1\")window.close()"},
    {type: "type", element: "#username", value: "admin", delay: 0.001},
    {type: "type", element: "#password", value: PASSWORD, delay: 0.001},
];