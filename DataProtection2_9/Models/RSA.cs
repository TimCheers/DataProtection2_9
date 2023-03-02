using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;

namespace DataProtection2_9
{
    public class RSA
    {
        public List<BigInteger> numbers = new List<BigInteger>();
        public List<BigInteger> BigKeys = new List<BigInteger>();
        public string text=" ";
        public BigInteger p;
        public string myOutput = "";
        public string alphabet = " qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNMйцукенгшщзхъфывапролджэячсмитьбюЙЦУКЕНГШЩЗХЪФЫВАПРОЛДЖЭЯЧСМИТЬБЮ1234567890!\"№;%:?*()@#$^&-=_+{}[]\\|/<>.,'`ёЁ~";
        public BigInteger q;
        public BigInteger n;
        public BigInteger e;
        public BigInteger d;
        public BigInteger m;
        public List<BigInteger> result = new List<BigInteger>();
        public void GetNumbers()
        {
            //Pass the file path and file name to the StreamReader constructor
            StreamReader sr = new StreamReader("../12.txt");
            //Read the first line of text
            string line = sr.ReadLine();
            numbers.Add(BigInteger.Parse(line));
            //Continue to read until you reach end of file
            while (line != null)
            {
                //write the lie to console window
                Console.WriteLine(line);
                //Read the next line
                line = sr.ReadLine();
                if (line != null)
                {
                    numbers.Add(BigInteger.Parse(line));
                }
            }
            //close the file
            sr.Close();
        }
        public void CreatePQ()
        {
            Random random = new Random();
            int index = random.Next(0, numbers.Count);
            p = numbers[index];
            index = random.Next(0, numbers.Count);
            q = numbers[index];
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

        public void CreateKeys()
        {
            n = p * q;
            m = (p - 1) * (q - 1);

            BigInteger tmp = 1;

            if (IsSimpleBoth(m))
            {
                while ((m * tmp + 1) % d != 0)
                {
                    tmp++;
                }
                e = (m * tmp + 1) / d;
            }
        }

        public bool IsSimpleBoth(BigInteger a)
        {
            for (int i = 2; i < Math.Sqrt((double)a) + 1; i++)
            {
                if (IsSimple(i))
                {
                    if (a % i != 0)
                    {
                        d = i;
                        return true;
                    }
                }
            }
            return false;
        }

        public int Index(char symb)
        {
            for (int i = 0; i < alphabet.Length; i++)
            {
                if (symb == alphabet[i])
                    return i + 20;
            }
            return -1;
        }

        public List<BigInteger> CreateKeysList()
        {
            List<BigInteger> tmp = new List<BigInteger>();

            for (int i = 0; i < alphabet.Length; i++)
            {
                tmp.Add((i ^ e) % n);
            }

            return tmp;
        }

        public int SearchOfKey(BigInteger x)
        {
            for (int i = 0; i < result.Count; i++)
            {
                if (result[i] == x)
                    return i + 100;
            }
            return -1;
        }


        public string CreateCipher(string input)
        {
            text = "";
            myOutput = "";
            text = input;
            string outp = "";
            List<BigInteger> keys = new List<BigInteger>();
            List<BigInteger> output = new List<BigInteger>();
            /*input = input.ToLower();*/
            for (int i = 0; i < input.Length; i++)
            {
                keys.Add(Index(input[i]));
            }

            result = CreateKeysList();

            for (int i = 0; i < keys.Count; i++)
            {
                output.Add((keys[i] ^ e) % n);
            }

            outp = "";
            for (int i = 0; i < output.Count; i++)
            {
                outp += (char)(SearchOfKey(output[i]));
            }
            myOutput = outp;
            return outp;
        }
    }
}
