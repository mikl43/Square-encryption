using System;
using System.Collections.Generic;
using System.Text;

namespace Square
{
    //класс матода Square
    class Square
    {
        public Square()
        {
            MakePowTable(285, 2, false);
        }
        List<byte[]> ListInText;//text to encrypt or decrypt in blocks of 16 bytes текст для шифрования или дешифровки блоками по 16 байтов
        List<byte[,]> ListKeysRounds;//list consisting of primary key and keys for 8 rounds список состоящий из первичного ключа и ключей для 8 раундов
        //conversion table array массив таблицы преобразования
        byte[] table = {0xB1, 0xCE, 0xC3, 0x95, 0x5A, 0xAD, 0xE7, 0x02, 0x4D, 0x44, 0xFB, 0x91, 0x0C, 0x87, 0xA1, 0x50,
                            0xCB, 0x67, 0x54, 0xDD, 0x46, 0x8F, 0xE1, 0x4E, 0xF0, 0xFD, 0xFC, 0xEB, 0xF9, 0xC4, 0x1A, 0x6E,
                            0x5E, 0xF5, 0xCC, 0x8D, 0x1C, 0x56, 0x43, 0xFE, 0x07, 0x61, 0xF8, 0x75, 0x59, 0xFF, 0x03, 0x22,
                            0x8A, 0xD1, 0x13, 0xEE, 0x88, 0x00, 0x0E, 0x34, 0x15, 0x80, 0x94, 0xE3, 0xED, 0xB5, 0x53, 0x23,
                            0x4B, 0x47, 0x17, 0xA7, 0x90, 0x35, 0xAB, 0xD8, 0xB8, 0xDF, 0x4F, 0x57, 0x9A, 0x92, 0xDB, 0x1B,
                            0x3C, 0xC8, 0x99, 0x04, 0x8E, 0xE0, 0xD7, 0x7D, 0x85, 0xBB, 0x40, 0x2C, 0x3A, 0x45, 0xF1, 0x42,
                            0x65, 0x20, 0x41, 0x18, 0x72, 0x25, 0x93, 0x70, 0x36, 0x05, 0xF2, 0x0B, 0xA3, 0x79, 0xEC, 0x08,
                            0x27, 0x31, 0x32, 0xB6, 0x7C, 0xB0, 0x0A, 0x73, 0x5B, 0x7B, 0xB7, 0x81, 0xD2, 0x0D, 0x6A, 0x26,
                            0x9E, 0x58, 0x9C, 0x83, 0x74, 0xB3, 0xAC, 0x30, 0x7A, 0x69, 0x77, 0x0F, 0xAE, 0x21, 0xDE, 0xD0,
                            0x2E, 0x97, 0x10, 0xA4, 0x98, 0xA8, 0xD4, 0x68, 0x2D, 0x62, 0x29, 0x6D, 0x16, 0x49, 0x76, 0xC7,
                            0xE8, 0xC1, 0x96, 0x37, 0xE5, 0xCA, 0xF4, 0xE9, 0x63, 0x12, 0xC2, 0xA6, 0x14, 0xBC, 0xD3, 0x28,
                            0xAF, 0x2F, 0xE6, 0x24, 0x52, 0xC6, 0xA0, 0x09, 0xBD, 0x8C, 0xCF, 0x5D, 0x11, 0x5F, 0x01, 0xC5,
                            0x9F, 0x3D, 0xA2, 0x9B, 0xC9, 0x3B, 0xBE, 0x51, 0x19, 0x1F, 0x3F, 0x5C, 0xB2, 0xEF, 0x4A, 0xCD,
                            0xBF, 0xBA, 0x6F, 0x64, 0xD9, 0xF3, 0x3E, 0xB4, 0xAA, 0xDC, 0xD5, 0x06, 0xC0, 0x7E, 0xF6, 0x66,
                            0x6C, 0x84, 0x71, 0x38, 0xB9, 0x1D, 0x7F, 0x9D, 0x48, 0x8B, 0x2A, 0xDA, 0xA5, 0x33, 0x82, 0x39,
                            0xD6, 0x78, 0x86, 0xFA, 0xE4, 0x2B, 0xA9, 0x1E, 0x89, 0x60, 0x6B, 0xEA, 0x55, 0x4C, 0xF7, 0xE2};
        //encryption шифрование
        public byte[] Encryption(string text, string key)
        {
            //we form the keys формируем ключи
            SetKeysRounds(key);
            //we form blocks of 16 bytes in the list формируем в списке блоки из 16 байтов
            CreateListBlocksBytes(text);
            //text block encryption шифрования текстовых блоков
            return EncryptionProcess();
        }
        //дешифрование
        public byte[] Decryption(byte[] mas_bytes, string key)
        {
            //we form the keys формируем ключи
            SetKeysRounds(key);
            //we form blocks of 16 bytes in the list формируем в списке блоки из 16 байтов
            ListInText.Clear();
            int k = 0;
            byte[] masb = new byte[16];
            for (int i = 0; i < mas_bytes.Length; i++)
            {
                masb[k] = mas_bytes[i];
                k++;
                if (k == 16 || i == mas_bytes.Length - 1)
                {
                    k = 0;
                    ListInText.Add(masb);
                    masb = new byte[16];
                }
            }
            //text block encryption шифрования текстовых блоков
            return DecryptionProcess();
        }
        //getting null key and keys for 8 rounds based on primary key получение нулевого ключа и ключей для 8 раундов на основе первичного ключа
        private void SetKeysRounds(string key0)
        {
            ListKeysRounds = new List<byte[,]>();
            Encoding encoding = Encoding.GetEncoding("ASCII");
            byte[] mas_bytes = encoding.GetBytes(key0);
            ListKeysRounds.Add(GetInputBlock(mas_bytes));//get null key получаем нулевой ключ
            byte constant = 1;
            for(int i = 0; i < 8; i++)
            {
                byte[] mas_result = new byte[4];
                byte[,] key = new byte[4, 4];
                byte[,] pred_key = ListKeysRounds[i];
                byte[] mas1 = new byte[4];
                byte[] mas2 = new byte[4];
                byte[] mas_constant = new byte[4];
                mas_constant[3] = constant;
                //formation of the first line of the key формирование первой строки ключа
                for (int j = 0; j < 4; j++) mas1[j] = pred_key[0, j];
                for (int j = 0; j < 4; j++) mas2[j] = pred_key[3, j];
                byte temp = mas2[0];
                for (int j = 0; j < 3; j++) mas2[j] = mas2[j + 1];
                mas2[3] = temp;
                mas_result = AddGaul(mas1, mas2);
                mas_result = AddGaul(mas_result, mas_constant);
                for (int j = 0; j < 4; j++) key[0, j] = mas_result[j];
                //forming the remaining three key strings формирование остальных трех строк ключа
                for (int j = 1; j < 4; j++)
                {
                    for (int k = 0; k < 4; k++) mas1[k] = pred_key[j, k];
                    for (int k = 0; k < 4; k++) mas2[k] = key[j - 1, k];
                    mas_result = AddGaul(mas1, mas2);
                    for (int k = 0; k < 4; k++) key[j, k] = mas_result[k];
                }
                ListKeysRounds.Add(key);
                constant *= 2;
            }
        }
        //addition operation in the Gaul field of two words операция сложения в поле Гаула двух слов
        private byte[] AddGaul(byte[] mas1, byte[] mas2)
        {
            byte[] result = new byte[4];
            for (int i = 0; i < 4; i++) result[i] = (byte)(mas1[i] ^ mas2[i]);
            return result;
        }
        //generates text into a list in blocks of 16 bytes in UTF-8 encoding производит формирование в список текста в блоки по 16 байт в кодировке UTF-8
        private void CreateListBlocksBytes(string text)
        {
            ListInText = new List<byte[]>();
            Encoding encoding = Encoding.GetEncoding("UTF-8");
            byte[] mas_bytes = encoding.GetBytes(text);
            int k=0;
            byte[] masb = new byte[16];
            for (int i = 0; i < mas_bytes.Length; i++)
            {
                masb[k] = mas_bytes[i];
                k++;
                if (k == 16 || i==mas_bytes.Length-1)
                {
                    k = 0;
                    ListInText.Add(masb);
                    masb = new byte[16];
                }
            }
        }
        //block encryption шифрование блоками
        private byte[] EncryptionProcess()
        {
            List<byte[,]> ListResultBytes = new List<byte[,]>();
            for(int i = 0; i < ListInText.Count; i++)
            {
                //get the input data block получаем входной блок данных
                byte[,] input_state=GetInputBlock(ListInText[i]);
                //bitwise addition with key before first round побитовое сложение с ключем перед первым раундом
                input_state = AddRoundKey(input_state, ListKeysRounds[0]);
                //inverse linear transformation before the first round обратное линейное преобразование перед первым раундом
                input_state = ObrLinerPreob(input_state);
                //rounds раунды
                for (int j = 1; j <= 8; j++)
                {
                    //linear transformation линейное преобразование
                    input_state = LinerPreob(input_state);
                    //non-linear transformation нелинейное преобразование
                    input_state = NotLinerPreob(input_state);
                    //matrix transposition транспонирование матрицы
                    input_state = TransMatrix(input_state);
                    //addition with round key сложение с ключем раунда
                    input_state = AddRoundKey(input_state, ListKeysRounds[j]);
                }
                //add ciphertext to list добавляем зашифрованный текст в список
                ListResultBytes.Add(input_state);
            }
            return GetResultBytes(ListResultBytes);
        }
        //block decryption дешифрование блоками
        private byte[] DecryptionProcess()
        {
            List<byte[,]> ListResultBytes = new List<byte[,]>();
            for (int i = 0; i < ListInText.Count; i++)
            {
                //get the input data block получаем входной блок данных
                byte[,] input_state = GetInputBlock(ListInText[i]);
                //rounds
                for (int j = 1; j <= 8; j++)
                {
                    //addition with round key сложение с ключем раунда
                    input_state = AddRoundKey(input_state, ListKeysRounds[9-j]);
                    //matrix transposition транспонирование матрицы
                    input_state = TransMatrix(input_state);
                    //inverse non-linear transformation обратное нелинейное преобразование
                    input_state = ObrNotLinerPreob(input_state);
                    //non-linear transformation обратное линейное преобразование
                    input_state = ObrLinerPreob(input_state);
                }
                //linear transformation линейное преобразование
                input_state = LinerPreob(input_state);
                //bitwise addition with zero key побитовое сложение с нулевым ключем
                input_state = AddRoundKey(input_state, ListKeysRounds[0]);
                //add ciphertext to list добавляем зашифрованный текст в список
                ListResultBytes.Add(input_state);
            }
            return GetResultBytes(ListResultBytes);
        }
        //generating the result of encryption/decryption as an array of bytes формирование результата шифрования/дешифрования в виде массива байтов
        private byte[] GetResultBytes(List<byte[,]> ListResultBytes)
        {
            byte[] mas_result = new byte[ListResultBytes.Count * 16];
            int k = 0;
            for (int i = 0; i < ListResultBytes.Count; i++)
            {
                byte[,] matrix = ListResultBytes[i];
                for (int i1 = 0; i1 < 4; i1++)
                    for (int j1 = 0; j1 < 4; j1++)
                    {
                        mas_result[k] = matrix[i1, j1];
                        k++;
                    }
            }
            return mas_result;
        }
        //convert a block of 16 bytes into a matrix преобразуем блок из 16 байтов в матрицу
        private byte[,] GetInputBlock(byte [] masb)
        {
            byte [,] result=new byte[4, 4];
            int i = 0, j = 0;
            for (int k=0; k<masb.Length; k++)
            {
                result[i, j] = masb[k];
                j++;
                if (j == 4)
                {
                    j = 0;i++;
                }
            }
            return result;
        }
        //bitwise addition of state and key matrices побитовое сложение матриц состояния и ключа
        private byte[,] AddRoundKey(byte[,] input_state, byte[,] input_key)
        {
            byte[,] result = new byte[4, 4];
            for (int j = 0; j < 4; j++)
                for (int i = 0; i < 4; i++) result[i, j] = (byte)(input_key[i, j] ^ input_state[i, j]);
            return result;
        }
        //state matrix linear transformation линейное преобразование матрицы состояния
        private byte[,] LinerPreob(byte[,] input_state)
        {
            byte[,] coef = new byte[4, 4]{
                { 2, 3, 1, 1 },
                { 1, 2, 3, 1 },
                { 1, 1, 2, 3 },
                { 3, 1, 1, 2 }
            };
            byte[,] result = new byte[4, 4];
            byte temp;
            for(int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++) 
                {
                    temp = 0;
                    for (int k = 0; k < 4; k++)
                        temp ^= Mult(input_state[i, k], coef[k, j]);
                    result[i, j] = temp;
                }
            return result;
        }
        //inverse linear transformation обратное линейному преобразованию
        private byte[,] ObrLinerPreob(byte[,] input_state)
        {
            byte[,] result = new byte[4, 4];
            byte[,] coef = new byte[4, 4]{
                { 14, 11, 13, 9 },
                { 9, 14, 11, 13 },
                { 13, 09, 14, 11 },
                { 11, 13, 09, 14 }
            };
            byte temp;
            for(int i=0;i<4;i++)
                for(int j = 0; j < 4; j++)
                {
                    temp = 0;
                    for (int k = 0; k < 4; k++)
                        temp ^= Mult(input_state[i, k], coef[k, j]);
                    result[i, j] = temp;
                }
            return result;
        }
        //non-linear transformation of the state matrix нелинейное преобразование матрицы состояния
        private byte[,] NotLinerPreob(byte[,] input_state)
        {
            byte[,] result = new byte[4, 4];
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++) result[i, j] = table[input_state[i, j]];
            return result;
        }
        //inverse non-linear transformation of the state matrix обратное нелинейное преобразование матрицы состояния
        private byte[,] ObrNotLinerPreob(byte[,] input_state)
        {
            byte[,] result = new byte[4, 4];
            for(int i=0;i<4;i++)
                for(int j = 0; j < 4; j++)
                {
                    byte b = input_state[i, j];
                    for(int k=0;k<table.Length;k++)
                        if (b == table[k])
                        {
                            result[i, j] = (byte) k;
                            break;
                        }
                }
            return result;
        }
        //matrix transposition транспонирование матрицы
        private byte[,] TransMatrix(byte[,] input_state)
        {
            byte[,] result = new byte[4, 4];
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++) result[j, i] = input_state[i, j];
            return result;
        }
        //MULTIPLICATION AND DIVISION IN THE GALOIS FIELD GF(256) УМНОЖЕНИЕ И ДЕЛЕНИЕ В ПОЛЕ ГАЛУА GF(256)
        private byte[] GF_256_power_a;
        private byte[] GF_256_log_a;
        private void MakePowTable(uint New_GF_Byte_poly, uint New_GF_Byte_prim_memb, bool ShowMessageboxes)
        {
            //If there is a multiplication function, then it is not difficult to compile a table of powers and logarithms, because exponentiation is a multiplication several times in a row.
            //Here, a table of degrees is created by the method of successive multiplication of a primitive member(as a rule, the number 2 is chosen, but here it can be any number).
            //The table is then checked for duplicate values.
            //If there are no duplicate values, then the selected primitive term and the generating polynomial are stored along with the computed tables.
            //The following values ​​are valid for the New_GF_Byte_prim_memb parameter: 285, 299, 301, 333, 351, 355, 357, 361, 369, 391, 397, 425, 251, 463, 487, 501.
            //This array can be made one less, since for the field GF[256] it is true that a ^ 0 = ^255, but in order not to get confused, I leave 256 elements of the array.
            //Если есть функция умножения, то составить таблицу степеней и логарифмов
            //не составляет никакого труда, ведь возведение в степень – есть умножение
            //несколько раз подряд
            //Здесь создаётся таблица степеней методом последовательного умножения
            //примитивного члена (как правило выбирают число 2, но здесь это может
            //быть любое число).
            //Затем таблица проверяется на наличие повторяющихся значений. Если нет
            //повторяющихся значений, то выбранный примитивный член и порождающий
            //полином сохраняются вместе с вычисленными таблицами.
            //для параметра New_GF_Byte_prim_memb валидны следующие значения:
            //285, 299, 301, 333, 351, 355, 357, 361, 369, 391, 397, 425, 251, 463,
            //487, 501.

            //Этот массив можно сделать на единицу меньше, так как для поля GF[256]
            //верно, что a^0= ^255, но чтобы не путаться оставляю 256 элементов массива.
            byte[] tmp_GF_256_power_a = new byte[256];
            byte[] tmp_GF_256_log_a = new byte[256];
            GF_256_power_a = new byte[256];
            GF_256_log_a = new byte[256];

            uint tmp_GF_Byte_poly = New_GF_Byte_poly;
            uint tmp_GF_Byte_prim_memb = New_GF_Byte_prim_memb;

            //Let's write trivial things like this: a^0=1 and a^1=a, and vice versa Пропишем тривиальные вещи как то: a^0=1 и a^1=a, и наоборот
            tmp_GF_256_power_a[0] = 1;
            tmp_GF_256_log_a[1] = 0;
            tmp_GF_256_power_a[1] = (byte)tmp_GF_Byte_prim_memb;
            tmp_GF_256_log_a[tmp_GF_Byte_prim_memb] = 1;
            //Other members of the field Остальные члены поля
            for (int i = 2; i < 256; i++)
            {
                tmp_GF_256_power_a[i] = (byte)Galois_b2_ext_mult(tmp_GF_Byte_prim_memb, tmp_GF_256_power_a[i - 1], tmp_GF_Byte_poly);
                //For the degree value "0" there are 2 values: 1 and 255. This must be taken into account Для значения степени "0" тут проходят 2 значения: 1 и 255. Это надо учесть
                if (0 != tmp_GF_256_power_a[i])
                {
                    tmp_GF_256_log_a[tmp_GF_256_power_a[i]] = (byte)i;
                }
            }

            bool Ok = true;
            //For the field GF[256] it is true that a^0 = a^255. So the check does not affect the power of 255
            //Для поля GF[256] верно, что a^0 = a^255. Так что проверка
            //не затрагивает степень 255
            for (int i = 0; i <= 254; i++)
            {
                for (int j = 0; j <= 254; j++)
                {
                    if (i != j)
                    {
                        if (tmp_GF_256_power_a[i] == tmp_GF_256_power_a[j])
                        {
                            Ok = false;
                        }
                    }
                }
            }
            //Copy to used tables if there are no repetitions in the table of degrees of the selected primitive member
            //Копируем в используемые таблицы, если нет повторов в таблице
            //степеней выбранного примитивного члена
            if (Ok)
            {
                for (int i = 0; i < 256; i++)
                {
                    GF_256_power_a[i] = tmp_GF_256_power_a[i];
                }
                for (int i = 0; i < 256; i++)
                {
                    GF_256_log_a[i] = tmp_GF_256_log_a[i];
                }
                //GF_256_poly = tmp_GF_Byte_poly;
                //GF_256_prim_memb = tmp_GF_Byte_prim_memb;
            }
        }

        private uint Galois_b2_ext_mult(uint m1, uint m2, uint Poly)
        {
            if (0 == m1 || 0 == m2) { return 0; }
            uint m1_tmp = m1;
            uint m2_tmp;
            uint m1_bit_num = 0;
            //Multiplying two polynomials using modulo 2 arithmetic is fairly straightforward.
            //We sort through the ones and zeros(for each bit of the first number, we sort through all the bits of the second(or vice versa)),
            //add the position numbers of the bits, but not always, but only when both sorted bits are ones, and invert the bit
            //of the result with a number equal to the sum of the positions for the given search step(inversion is the addition of one modulo 2)
            //Перемножение двух полиномов, при использовании арифметики по модулю 2 достаточно простое занятие.
            //перебираем единички и нолики (для каждого бита первого числа перебираем все биты второго (или наоборот)), складываем номера позиций битов,
            //но не всегда, а только когда оба перебираемых бита - единицы, и инвертируем бит результата под номером, равном сумме позиций для данного шага перебора
            //(инверсия - это прибавление единицы по модулю 2)
            uint PolyMultRez = 0;

            while (m1_tmp != 0)
            {
                uint bit_m1 = (m1_tmp & 1u) == 0u ? 0u : 1u;
                m1_tmp = m1_tmp >> 1;
                m2_tmp = m2;
                uint m2_bit_num;
                m2_bit_num = 0;
                while (m2_tmp != 0)
                {
                    uint bit_m2 = (m2_tmp & 1u) == 0u ? 0u : 1u;
                    m2_tmp = m2_tmp >> 1;
                    if ((bit_m1 != 0) && (bit_m2 != 0))
                    {
                        int BitNum = (int)(m2_bit_num + m1_bit_num);
                        PolyMultRez ^= 1u << BitNum;
                    }
                    m2_bit_num = m2_bit_num + 1;
                }
                m1_bit_num = m1_bit_num + 1;
            }
            //Here is the result of multiplying PolyMultRez polynomials. It remains to find the remainder after dividing by the chosen generating polynomial.
            //The division of polynomials is as follows: We take the highest degree of the dividend, and subtract the highest degree of the divisor.
            //We get a number - the degree of the quotient
            //Now we multiply, but in fact, we simply add to each degree of the divisor the degree of the resulting quotient and repeat everything in a circle until the degree of the divisible is less than the degree of the divisor
            //Тут есть результат умножения полиномов PolyMultRez. Осталось найти остаток от деления на выбранный порождающий полином.
            //Деление полиномов происходит так: Берём старшую степень делимого, и вычитаем старшую степень делителя. 
            //Получаем число - степень частного
            //Теперь перемножаем, а по сути, просто прибавляем к каждой степени делителя степень получившегося частного
            //и повторяем всё по кругу, пока степень делимого не окажется меньше степени делителя
            uint TmpDivisor_lead_bit_n;
            uint TmpQuotient;
            uint TmpDivisor = Poly;
            uint TmpDividend = PolyMultRez;
            uint TmpDividend_LeadBitNum;
            uint TmpMult_bitNum;
            uint TmpMult_rez;

            TmpDividend_LeadBitNum = GetLeadBitNum(TmpDividend);
            TmpDivisor_lead_bit_n = GetLeadBitNum(TmpDivisor);

            while (TmpDividend_LeadBitNum >= TmpDivisor_lead_bit_n)
            {

                TmpQuotient = (TmpDividend_LeadBitNum - TmpDivisor_lead_bit_n);

                TmpMult_bitNum = 0;
                TmpMult_rez = 0;
                while (TmpDivisor != 0)
                {
                    uint bit_TmpMult = (TmpDivisor & 1u) == 0u ? 0u : 1u;
                    TmpDivisor >>= 1;
                    TmpMult_rez ^= bit_TmpMult << (int)(TmpQuotient + TmpMult_bitNum);
                    TmpMult_bitNum = TmpMult_bitNum + 1;
                }
                TmpDividend = TmpDividend ^ TmpMult_rez;
                TmpDivisor = Poly;
                TmpDividend_LeadBitNum = GetLeadBitNum(TmpDividend);
            }
            //The result of multiplying numbers is the remainder of dividing the product of polynomials by the generating polynomial.
            //Результат умножения числел есть остаток от деления произведения многочленов на порождающий полином.
            return TmpDividend;
        }
        private byte Pow_a(int Degr)
        {
            //Raising a primitive member to a power.The degree property in the Galois field GF[256] is such that the degree of the primitive term 0 is equal
            //to the degree 255; 1 - 256; 2 - 527 and so on.
            //Возведение примитивного члена в степень. Свойство степени в поле 
            //Галуа GF[256] таково, что степень примитивного члена 0 равна
            //степени 255; 1 - 256; 2 - 527 и так далее.
            if (0 <= Degr && Degr < 255)
            {
                return GF_256_power_a[Degr];
            }
            else
            {
                int TmpDegr = IntMod(Degr);
                TmpDegr %= 255;
                //Although there are no negative numbers in the Galois field, here a negative exponent means the reciprocal of the number.
                //Хоть и не существует отрицательных чисел в поле Галуа, здесь под
                //отрицательной степенью подразумевается число обратное.
                if (Degr < 0)
                {
                    TmpDegr = 255 - TmpDegr;
                }
                return GF_256_power_a[TmpDegr];
            }
        }

        private byte Log_a(byte Arg)
        {
            //Logarithm to the base of the primitive term Логарифм по основанию примитивного члена
            if (0 == Arg)
            {
                throw new Exception("Argument cannot be zero in GF_Byte.Log_a(Arg)");
                //The logarithm of unity in GF[256] is zero and 255 because a^0 == a ^ 255.
                //For Reed-Solomon coding, choose 0.
                //Логарифм единицы в GF[256] равен нулю и 255, так как a^0==a^255.
                //Для кодирования Рида-Соломона выбираем 0.
            }
            else if (1 == Arg)
            {
                return 0;
            }
            else
            {
                return GF_256_log_a[Arg];
            }
        }
        private int IntMod(int Arg)
        {
            if (Arg >= 0)
            {
                return (Int32)Arg;
            }
            else
            {
                return (Int32)(-Arg);
            }
        }
        private uint GetLeadBitNum(UInt32 Val)
        {
            if (0 == Val) return 0;
            int BitNum = 31;
            uint CmpVal = 1u << BitNum;
            while (Val < CmpVal)
            {
                CmpVal >>= 1;
                BitNum--;
            }
            return (uint)BitNum;
        }

        private byte Mult(byte m1, byte m2)
        {
            //Multiplication using power tables and logarithms.
            //Pretty fast operation.
            //Умножение с использованием таблиц степеней и логарифмов.
            //Довольно таки быстрая операция
            if (0 == m1 || 0 == m2) { return 0; }
            return Pow_a(Log_a(m1) + Log_a(m2));
        }
        //division is not used in the encryption algorithm
        //деление не используется в алгоритме шифрования
        private byte Div(byte d1, byte d2)
        {
            //Division using power tables and logarithms.
            //Деление с использованием таблиц степеней и логарифмов.
            if (0 == d2) { throw new Exception("Division by zero"); }
            if (0 == d1) { return 0; }
            return Pow_a(Log_a(d1) - Log_a(d2));
        }
    }
}
