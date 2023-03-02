using DataProtection2_9.Models;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using System.Collections.Generic;
using System.Linq;

namespace DataProtection2_9.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private static RSA rsa = new RSA();
        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }
        private void Generate()
        {
            rsa.GetNumbers();
            rsa.CreatePQ();
            rsa.CreateKeys();
        }
        public IActionResult Index()
        {
            return View();
        }
        public IActionResult Privacy()
        {
            return View();
        }
        public IActionResult RSA_Method(string text)
        {
            if (!string.IsNullOrEmpty(text))
            {
                rsa.text = "";
                rsa.CreateCipher(text);
            }
                
            return View(rsa);
        }
        [HttpPost]
        public IActionResult Call_Generate()
        {
            Generate();
            return RedirectToAction("RSA_Method");
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}