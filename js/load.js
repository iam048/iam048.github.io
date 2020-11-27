/**
  * @param {String} url - address for the HTML to fetch
  * @return {String} the resulting HTML string fragment
  */
async function fetchHtmlAsText(url) {
    return await (await fetch(url)).text();
}

// this is your `load_home() function`
async function loadHome() {
    const contentDiv = document.getElementById("content");
    contentDiv.innerHTML = await fetchHtmlAsText("test.html");
}

async function loadArticles() {
    const contentDiv = document.getElementById("content");
    contentDiv.innerHTML = await fetchHtmlAsText("");
}

async function loadHome() {
    const contentDiv = document.getElementById("content");
    contentDiv.innerHTML = await fetchHtmlAsText("test.html");
}

async function loadHome() {
    const contentDiv = document.getElementById("content");
    contentDiv.innerHTML = await fetchHtmlAsText("test.html");
}

async function loadHome() {
    const contentDiv = document.getElementById("content");
    contentDiv.innerHTML = await fetchHtmlAsText("test.html");
}

async function loadHome() {
    const contentDiv = document.getElementById("content");
    contentDiv.innerHTML = await fetchHtmlAsText("test.html");
}

async function loadHome() {
    const contentDiv = document.getElementById("content");
    contentDiv.innerHTML = await fetchHtmlAsText("test.html");
}

async function loadHome() {
    const contentDiv = document.getElementById("content");
    contentDiv.innerHTML = await fetchHtmlAsText("test.html");
}