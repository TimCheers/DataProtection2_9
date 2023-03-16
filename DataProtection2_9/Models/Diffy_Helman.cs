using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;

namespace DataProtection2_9
{
    public class Diffy_Helman
    {
        public BigInteger A;
        public BigInteger B;
        public BigInteger Kx;

        public BigInteger Ky;

        public BigInteger x;
        public BigInteger y;

        public BigInteger p;
        public BigInteger g;
        public string alphabet = " qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNMйцукенгшщзхъфывапролджэячсмитьбюЙЦУКЕНГШЩЗХЪФЫВАПРОЛДЖЭЯЧСМИТЬБЮ1234567890!\"№;%:?*()@#$^&-=_+{}[]\\|/<>.,'`ёЁ~";
        public string text = " ";
        public string myOutput = "";

        private Random rn = new Random();

        public List<BigInteger> simple20 = new List<BigInteger>();
        public List<BigInteger> simple = new List<BigInteger>();

        public void GetNumbers()
        {
            StreamReader sr = new StreamReader("../20.txt");
            string line = sr.ReadLine();
            simple20.Add(BigInteger.Parse(line));
            while (line != null)
            {
                Console.WriteLine(line);
                line = sr.ReadLine();
                if (line != null)
                {
                    simple20.Add(BigInteger.Parse(line));
                }
            }
            //close the file
            sr.Close();
        }

        public void GetSimple()
        {
            StreamReader sr = new StreamReader("../simple.txt");
            string line = sr.ReadLine();
            simple.Add(BigInteger.Parse(line));
            while (line != null)
            {
                Console.WriteLine(line);
                line = sr.ReadLine();
                if (line != null)
                {
                    simple.Add(BigInteger.Parse(line));
                }
            }
            //close the file
            sr.Close();
        }

        public void CreatePQ()
        {
            int index = rn.Next(0, simple.Count);
            p = simple[index];

            g = CreateQ(p);
        }

        public static bool IsSimple(BigInteger number)
        {
            if (number == 2) return true;
            for (int i = 2; i < Math.Sqrt((double)number) + 1; i++)
            {
                if (number % i == 0)
                {
                    return false;
                }
            }
            return true;
        }

        public BigInteger CreateQ(BigInteger x)
        {
            List<BigInteger> fact = new List<BigInteger>();
            BigInteger phi = p - 1, n = phi;
            for (int i = 2; i * i <= n; ++i)
            {
                if (n % i == 0)
                {
                    fact.Add(i);
                    while (n % i == 0)
                        n /= i;
                }
            }
            if (n > 1)
                fact.Add(n);
            for (int res = 2; res <= p; ++res)
            {
                bool ok = true;
                for (int i = 0; i < fact.Count && ok; ++i)
                    ok &= BigInteger.ModPow(res, phi / fact[i], p) != 1;
                if (ok) return res;
            }
            return -1;
        }


        //Простые 20-разрядные числа
        public void CreateXY()
        {
            int index = rn.Next(0, simple20.Count);
            x = simple20[index];
            index = rn.Next(0, simple20.Count);
            y = simple20[index]; ;
        }

        public void CreateABK()
        {
            A = BigInteger.ModPow(g, x, p);
            B = BigInteger.ModPow(g, y, p);
            Kx = BigInteger.ModPow(B, x, p);
            Ky = BigInteger.ModPow(A, y, p);
        }

        public List<BigInteger> CreateCipher(string input)
        {
            text = input;
            List<BigInteger> output = new List<BigInteger>();
            for (int i = 0; i < input.Length; i++)
            {
                BigInteger tmp = BigInteger.ModPow((int)(input[i]), Kx, 1000000001);
                //BigInteger tmp = BigInteger.Pow(GetIndex(input[i]), (int)Kx);

                output.Add(tmp);
            }
            string[] arr = output.Select(i => i.ToString()).ToArray();
            for(int i =0; i < arr.Length; i++)
                myOutput+=arr[i];
            return output;
        }

        public int GetIndex(char a)
        {
            for (int i = 0; i < alphabet.Length; i++)
            {
                if (a == alphabet[i])
                    return (i + 1);
            }
            return -1;
        }
    }
}
