var div=document.createElement("div");
div.id="preloader",
div.className="preloader",
div.innerHTML='<div class="black_wall"></div><div class="loader"></div>',
document.body.insertBefore(div,document.body.firstChild),
window.onload=function()
	{
		document.getElementById("preloader").classList.add("off")
	};