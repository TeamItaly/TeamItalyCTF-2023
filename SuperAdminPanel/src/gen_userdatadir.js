import chrome from "puppeteer"
import fs from 'fs'
import dotenv from 'dotenv'
import child_process from 'child_process'
fs.mkdirSync("./userdatadir", {recursive: true})
let browser = await chrome.launch({
    "userDataDir": "./userdatadir",
    "headless": false
})
let c = await browser.newPage()
