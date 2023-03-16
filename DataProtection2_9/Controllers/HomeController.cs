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
        private static DES_cipher des = new DES_cipher();
        private static DESContent desContet = new DESContent();
        private static Diffy_Helman dh = new Diffy_Helman();
        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }
        private void GenerateRSA()
        {
            rsa.GetNumbers();
            rsa.CreatePQ();
            rsa.CreateKeys();
        }
        private void GenerateDiffy()
        {
            dh.GetNumbers();
            dh.GetSimple();
            dh.CreateXY();
            dh.CreatePQ();
            dh.CreateABK();
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
        public IActionResult Diffy_Helman(string text)
        {
            if (!string.IsNullOrEmpty(text))
            {
                dh.text = "";
                dh.CreateCipher(text);
            }

            return View(dh);
        }

        [HttpPost]
        public IActionResult Call_GenerateRSA()
        {
            GenerateRSA();
            return RedirectToAction("RSA_Method");
        }
        [HttpPost]
        public IActionResult Call_GenerateDiffy()
        {
            GenerateDiffy();
            return RedirectToAction("Diffy_Helman");
        }
        public IActionResult DES_cipher()
        {
            return View(desContet);
        }
        [HttpPost]
        public IActionResult EncodeDES(string encryptionString, string encryptionKey)
        {
            string s = encryptionString;
            string key = encryptionKey;
            desContet.encryptionKey = key;
            desContet.encryptionString = encryptionString;

            des.CutStringIntoBlocks(s);

            key = des.CorrectKeyWord(key, s.Length / (2 * des.Blocks.Length));
            //textBoxEncodeKeyWord.Text = key;
            key = des.StringToBinaryFormat(key);

            for (int j = 0; j < 16; j++)
            {
                for (int i = 0; i < des.Blocks.Length; i++)
                    des.Blocks[i] = des.EncodeDES_One_Round(des.Blocks[i], key);

                key = des.KeyToNextRound(key);
            }

            key = des.KeyToPrevRound(key);

            key = des.StringFromBinaryToNormalFormat(key);

            string result = "";

            for (int i = 0; i < des.Blocks.Length; i++)
                result += des.Blocks[i];

            result = des.StringFromBinaryToNormalFormat(result);

            desContet.decryptionString = result;
            desContet.encryptionKey = key;
            return RedirectToAction("DES_cipher");
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}