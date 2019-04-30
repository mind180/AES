using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;

namespace AES
{
    class Aes
    {
        //------------------------------ BOXES ------------------------------
        static byte[] Rcon = {
            0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };
        //----------------------------------------------------------------------

        //--------------------data-----------
        static byte Nb = 4;//number of column(32-bits of each symbol)
        static byte Nk = 4;//number of 32-bits words of key
        static byte Nr = 10;//number of rounds

        public static void setNk( byte value )
        {
            Nk = value;

            if (Nk == 4)
                Nr = 10;
            else if (Nk == 6)
                Nr = 12;
            else if (Nk == 8)
                Nr = 14;
            
        }

        public static byte getNk()
        {
            return Nk;
        }
             
        byte[,] KeyShedule = new byte[ 4, Nb * (Nr + 1) ];
        //-----------------------------------------------------------------------

       
        //-------------------------------------- AES function implementation ------------------------------------------

        static public byte[] Encrypt(byte[] input, byte[] key)
        {
            byte[] lastBlock = new byte[16];


            //------------transform last block to 16 symbols------------
            byte rest = (byte)(input.Count() % 16);//get rest

            // fill last blocks
            if (rest != 0)
            {
                //-----------------prapare last block-----------------------
                for (int i = 0; i < rest; i++)
                    lastBlock[i] = input[(input.Count() - rest) + i];

                for (int i = rest; i < 16; i++)
                    lastBlock[i] = rest;// fill by rest value
                //---------------------------------------------------------

                byte[] temp = input;
                input = new byte[(input.Count() - rest) + 32];

                //copy temp
                for (int i = 0; i < input.Count() - 32; i++)
                {
                    input[i] = temp[i];
                }

                // copy last block
                for (int i = 0; i < 16; i++)
                {
                    input[(input.Count() - 32) + i] = lastBlock[i];
                }

            }


            //---------------------------------------------------------
            byte[,] state = new byte[4, Nb];
            byte[] output = new byte[input.Count()];

            for (int offset = 0; offset < input.Count() - 16; offset += 16)
            {//--------------------------------------
                for (int r = 0; r < 4; r++)
                {
                    for (int c = 0; c < Nb; c++)
                    {
                        state[r, c] = input[(r + 4 * c) + offset];

                    }
                }//end fill state

               

                //---ciphering one state---
                Cipher(state, key);

                //-------------------------

                for (int r = 0; r < 4; r++)
                {
                    for (int c = 0; c < Nb; c++)
                    {
                        output[(r + 4 * c) + offset] = state[r, c];
                    }
                }//end output state

            }//end offset for

            if (rest != 0)
            {
                //last block with ones
                for (int i = 0; i < 16; i++)
                {
                    output[(output.Count() - 16) + i] = 0x1;
                }
            }
            else
            {
                //last block with zeros
                for (int i = 0; i < 16; i++)
                {
                    output[(output.Count() - 16) + i] = 0x0;
                }
            }


            return output;
        }
        //---------------------------------------------------------------------------------------------------


        static public byte[] Encrypt( byte[] input, byte[] key, ref String res )
        {
            byte[] lastBlock = new byte[16];

                        
            //------------transform last block to 16 symbols------------
            byte rest = (byte)(input.Count() % 16);//get rest

            // fill last blocks
            if ( rest != 0 )
            {
                //-----------------prapare last block-----------------------
                for(int i = 0; i < rest; i++)
                    lastBlock[i] = input[ (input.Count() - rest) + i ];
                
                for(int i = rest; i < 16; i++)
                    lastBlock[i] = rest;// fill by rest value
                //---------------------------------------------------------

                byte[] temp = input;
                input = new byte[ (input.Count() - rest) + 32 ];

                //copy temp
                for ( int i = 0; i < input.Count() - 32; i++ )
                {
                    input[i] = temp[i];
                }

                // copy last block
                for (int i = 0; i < 16; i++)
                {
                    input[ (input.Count() - 32) + i ] = lastBlock[i];
                }
                                
            }
           

            //---------------------------------------------------------
            byte[,] state = new byte[4, Nb];
            byte[] output = new byte[ input.Count() ];

            for ( int offset = 0; offset < input.Count()-16; offset += 16 )
            {//--------------------------------------
                for (int r = 0; r < 4; r++)
                {
                    for (int c = 0; c < Nb; c++)
                    {
                        state[r, c] = input[ (r + 4*c) + offset ];
                        
                    }
                }//end fill state

                res += "-----------------------------------------------------\n";
                res += "   State: \n";
                byte[] buff = new byte[Nb];
                for (int r = 0; r < 4; r++)
                {
                    for (int c = 0; c < Nb; c++)
                    {
                        buff[c] = state[r, c];
                       
                    }
                    res += BitConverter.ToString(buff);
                    res += "\n";
                }//end copy state to res
                res += "\n";

                //---ciphering one state---
                Cipher(state, key, ref res);
                
                //-------------------------

                for (int r = 0; r < 4; r++)
                {
                    for (int c = 0; c < Nb; c++)
                    {
                        output[(r + 4 * c) + offset] = state[r, c];
                    }
                }//end output state

            }//end offset for

            if (rest != 0)
            {
                //last block with ones
                for (int i = 0; i < 16; i++)
                {
                    output[(output.Count() - 16) + i] = 0x1;
                }
            }
            else
            {
                //last block with zeros
                for (int i = 0; i < 16; i++)
                {
                    output[(output.Count() - 16) + i] = 0x0;
                }
            }


            return output;
        }

        static public byte[] Decrypt(byte[] input, byte[] key)
        {
            byte[,] state = new byte[4, Nb];
            byte[] output = new byte[input.Count()];

            for (int offset = 0; offset < input.Count(); offset += 16)
            {//--------------------------------------
                for (int r = 0; r < 4; r++)
                {
                    for (int c = 0; c < Nb; c++)
                    {
                        state[r, c] = input[(r + 4 * c) + offset];
                        
                    }
                }//end fill state

                //---ciphering one state---

                InvCipher(state, key);

                //-------------------------

                for (int r = 0; r < 4; r++)
                {
                    for (int c = 0; c < Nb; c++)
                    {
                        output[(r + 4 * c) + offset] = state[r, c];
                    }
                }//end output state

            }//end offset for

            return output;
        }

       


        //-------------------------------------------------------------------------------------------------------------
        // ENCRYPT main function
        //res is external variable 
        static void Cipher( byte[,] state, byte[] key, ref String res )
        {
            byte round;
            byte[,] KeyShedule = new byte[4, Nb * (Nr + 1)];
            byte[] buff = new byte[Nb * (Nr + 1)];
            byte[] buf = new byte[Nb];

            System.Diagnostics.Stopwatch sw = new Stopwatch();
            sw.Start();
            KeyExpansion(KeyShedule, key);
            sw.Stop();

            res += "   Key Shedule:\n";

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < Nb * (Nr + 1); j++)
                {
                    buff[j] = KeyShedule[i, j];
                }
                res += BitConverter.ToString( buff );
                res += "\n";
            }
            res += "Время вычисления Key Shedule = ";
            res += (sw.Elapsed).ToString();

            sw.Start();
            AddRoundKey(0, state, KeyShedule);
            sw.Stop();

            res += "\n                      ROUND 0\n";
            res += "            after AddRoundKey(): \n";
            for (int r = 0; r < 4; r++)
            {
                for (int c = 0; c < Nb; c++)
                {
                    buf[c] = state[r, c];
                }
                res += BitConverter.ToString(buf);
                res += "\n";
            }//end copy state to res
            res += "\nВремя вычисления AddRoundKey() = ";
            res += (sw.Elapsed).ToString() + "\n";
            
            for (round = 1; round < Nr; round++)
            {
                res += "\n                      ROUND "+ round.ToString() + "\n";
                res += "\n            after SubBytes():\n";
                sw.Start();
                SubBytes(state);
                sw.Stop();
                for (int r = 0; r < 4; r++)
                {
                    for (int c = 0; c < Nb; c++)
                    {
                        buf[c] = state[r, c];
                    }
                    res += BitConverter.ToString(buf);
                    res += "\n";
                }//end copy state to res
                res += "Время вычисления SubBytes() = ";
                res += (sw.Elapsed).ToString() + "\n";


                res += "\n            after ShiftRows():\n";
                sw.Start();
                ShiftRows(state);
                sw.Stop();
                for (int r = 0; r < 4; r++)
                {
                    for (int c = 0; c < Nb; c++)
                    {
                        buf[c] = state[r, c];
                    }
                    res += BitConverter.ToString(buf);
                    res += "\n";
                }//end copy state to res
                res += "Время вычисления ShiftRows() = ";
                res += (sw.Elapsed).ToString() + "\n";


                res += "\n            after MixColumns():\n";
                sw.Start();
                MixColumns(state);
                sw.Stop();
                for (int r = 0; r < 4; r++)
                {
                    for (int c = 0; c < Nb; c++)
                    {
                        buf[c] = state[r, c];
                    }
                    res += BitConverter.ToString(buf);
                    res += "\n";
                }//end copy state to res
                res += "Время вычисления MixColumns() = ";
                res += (sw.Elapsed).ToString() + "\n";


                res += "\n       after AddRoundKey():\n";
                sw.Start();
                AddRoundKey(round, state, KeyShedule);
                sw.Stop();
                for (int r = 0; r < 4; r++)
                {
                    for (int c = 0; c < Nb; c++)
                    {
                        buf[c] = state[r, c];
                    }
                    res += BitConverter.ToString(buf);
                    res += "\n";
                }//end copy state to res
                res += "Время вычисления AddRoundKey() = ";
                res += (sw.Elapsed).ToString() + "\n";

            }

            res += "\n                      ROUND " + round.ToString() + " (last round)\n";

            res += "\n            after SubBytes():\n";
            sw.Start();
            SubBytes(state);
            sw.Stop();
            for (int r = 0; r < 4; r++)
            {
                for (int c = 0; c < Nb; c++)
                {
                    buf[c] = state[r, c];
                }
                res += BitConverter.ToString(buf);
                res += "\n";
            }//end copy state to res
            res += "Время вычисления SubBytes() = ";
            res += (sw.Elapsed).ToString() + "\n";

            
            res += "\n            after ShiftRows():\n";
            sw.Start();
            ShiftRows(state);
            sw.Stop();
            for (int r = 0; r < 4; r++)
            {
                for (int c = 0; c < Nb; c++)
                {
                    buf[c] = state[r, c];
                }
                res += BitConverter.ToString(buf);
                res += "\n";
            }//end copy state to res
            
            res += "Время вычисления ShiftRows() = ";
            res += (sw.Elapsed).ToString() + "\n";


            res += "\n        after AddRoundKey():\n";
            sw.Start();
            AddRoundKey(round, state, KeyShedule);
            sw.Stop();
            for (int r = 0; r < 4; r++)
            {
                for (int c = 0; c < Nb; c++)
                {
                    buf[c] = state[r, c];
                }
                res += BitConverter.ToString(buf);
                res += "\n";
            }//end copy state to res
            res += "Время вычисления AddRoundKey() = ";
            res += (sw.Elapsed).ToString() + "\n";


            res += "\n----------------------------------------------------------------\n";
        }

        //--------------------------------------------------------
        static void Cipher( byte[,] state, byte[] key )
        {
            byte round;
            byte[,] KeyShedule = new byte[4, Nb * (Nr + 1)];
            byte[] buff = new byte[Nb * (Nr + 1)];

            KeyExpansion(KeyShedule, key);
           
           
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < Nb * (Nr + 1); j++)
                {
                    buff[j] = KeyShedule[i, j];
                }
           
            }
           



            AddRoundKey(0, state, KeyShedule);

            for (round = 1; round < Nr; round++)
            {
                SubBytes(state);
                ShiftRows(state);
                MixColumns(state);
                AddRoundKey(round, state, KeyShedule);
            }

            SubBytes(state);
            ShiftRows(state);
            AddRoundKey(round, state, KeyShedule);

        }

        //-------------------------------------------------------------------------------------------------------

     

        // This function produces Nb*(Nr+1) round keys. The round keys are used in each round to decrypt the states.
        static void KeyExpansion(byte[,] RoundKey, byte[] Key)
        {
            byte i, j, k;
            byte[] tempa = new byte[4]; // Used for the column/row operations

            // The first round key is the key itself.
            for (i = 0; i < Nk; ++i)
            {
                RoundKey[ 0, i ] = Key[ (i * 4) + 0 ];
                RoundKey[ 1, i ] = Key[ (i * 4) + 1 ];
                RoundKey[ 2, i ] = Key[ (i * 4) + 2 ];
                RoundKey[ 3, i ] = Key[ (i * 4) + 3 ];
            }
            //-------------------------------------------

            // All other round keys are found from the previous round keys.
            for (i = Nk; i < (Nr + 1) * Nb; ++i)//each column                                         !!!!!!!!!
            {

                {
                    //k = (byte)((i - 1) * 4);//every 4 column
                    tempa[0] = RoundKey[ 0, i-1 ];
                    tempa[1] = RoundKey[ 1, i-1 ];
                    tempa[2] = RoundKey[ 2, i-1 ];
                    tempa[3] = RoundKey[ 3, i-1 ];
                }

                if (i % Nk == 0)
                {
                    // This function shifts the 4 bytes in a word to the left once.
                    // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]
                    // Function RotWord()
                    {
                        byte temp = tempa[0];
                        tempa[0] = tempa[1];
                        tempa[1] = tempa[2];
                        tempa[2] = tempa[3];
                        tempa[3] = temp;
                    }

                    // SubWord() is a function that takes a four-byte input word and
                    // applies the S-box to each of the four bytes to produce an output word.
                    // Function Subword()
                    {
                        tempa[0] = Boxes.getSBoxValue(tempa[0]);
                        tempa[1] = Boxes.getSBoxValue(tempa[1]);
                        tempa[2] = Boxes.getSBoxValue(tempa[2]);
                        tempa[3] = Boxes.getSBoxValue(tempa[3]);
                    }

                    // Function Xor: W(i-nk) ^ W(i-1) ^  Rcon(i/nk-1) 
                    {
                        tempa[0] = (byte)(RoundKey[0, i - Nk] ^ tempa[0] ^ Rcon[i / Nk]);
                        tempa[1] = (byte)(RoundKey[1, i - Nk] ^ tempa[1] );
                        tempa[2] = (byte)(RoundKey[2, i - Nk] ^ tempa[2] );
                        tempa[3] = (byte)(RoundKey[3, i - Nk] ^ tempa[3] );
                    }
                }
                else {
                    tempa[0] = (byte)( RoundKey[0, i - 1] ^ RoundKey[0, i - Nk ] );
                    tempa[1] = (byte)( RoundKey[1, i - 1] ^ RoundKey[1, i - Nk ] );
                    tempa[2] = (byte)( RoundKey[2, i - 1] ^ RoundKey[2, i - Nk ] );
                    tempa[3] = (byte)( RoundKey[3, i - 1] ^ RoundKey[3, i - Nk ] );      
                }
                //assigment
                {
                    RoundKey[0, i] = tempa[0]; 
                    RoundKey[1, i] = tempa[1];
                    RoundKey[2, i] = tempa[2];
                    RoundKey[3, i] = tempa[3];
                }

            }
        }

                
        // This function adds the round key to state.
        // The round key is added to the state by an XOR function.
        static public void AddRoundKey( byte round, byte[,] state, byte[,] RoundKey )
        {
            byte col, j;
            for ( col = 0; col < Nb; ++col )//                                                      !!!!!!!!!!!!!!!!
            {
                state[ 0, col ] = (byte)( state[ 0, col ] ^ RoundKey[ 0, Nb * round + col ] );
                state[ 1, col ] = (byte)( state[ 1, col ] ^ RoundKey[ 1, Nb * round + col ] );
                state[ 2, col ] = (byte)( state[ 2, col ] ^ RoundKey[ 2, Nb * round + col ] );
                state[ 3, col ] = (byte)( state[ 3, col ] ^ RoundKey[ 3, Nb * round + col ] );
            }
        }//static public void AddRoundKey

        
        // The SubBytes Function Substitutes the values in the
        // state matrix with values in an S-box.
        static void SubBytes( byte[,] state )
        {
            for (byte col = 0; col < Nb; ++col )
            {
                state[0, col] = Boxes.getSBoxValue(state[0, col]);
                state[1, col] = Boxes.getSBoxValue(state[1, col]);
                state[2, col] = Boxes.getSBoxValue(state[2, col]);
                state[3, col] = Boxes.getSBoxValue(state[3, col]);
                
            }
        }//end SubBytes()


        // The ShiftRows() function shifts the rows in the state to the left.
        // Each row is shifted with different offset.
        // Offset = Row number. So the first row is not shifted.
        static void ShiftRows(byte[,] state)
        {
            byte temp;

            // Rotate first row 1 columns to left  
            temp = state[1, 0];
            state[1, 0] = state[1, 1];
            state[1, 1] = state[1, 2];
            state[1, 2] = state[1, 3];
            state[1, 3] = temp;

            // Rotate second row 2 columns to left  
            temp = state[2, 0];
            state[2, 0] = state[2, 2];
            state[2, 2] = temp;

            temp = state[2, 1];
            state[2, 1] = state[2, 3];
            state[2, 3] = temp;

            // Rotate third row 3 columns to left
            temp = state[3, 0];
            state[3, 0] = state[3, 3];
            state[3, 3] = state[3, 2];
            state[3, 2] = state[3, 1];
            state[3, 1] = temp;
        }


     
        // MixColumns function mixes the columns of the state matrix
        static void MixColumns( byte[,] state )
        {
            byte i;
            for (i = 0; i < Nb; ++i)
            {
                byte s0 = (byte)( mul_by_02(state[0, i])^mul_by_03(state[1, i])^state[2, i]^state[3, i] );
                byte s1 = (byte)(state[0, i]^mul_by_02(state[1, i])^mul_by_03(state[2, i])^state[3, i]);
                byte s2 = (byte)(state[0, i]^state[1, i]^mul_by_02(state[2, i])^mul_by_03(state[3, i]) );
                byte s3 = (byte)(mul_by_03(state[0,i]) ^ state[1,i] ^ state[2, i] ^ mul_by_02(state[3, i]) );

                state[0, i] = s0;
                state[1, i] = s1;
                state[2, i] = s2;
                state[3, i] = s3;
            }
        }

        //additional function for MixColumns --------------------------------------------------------------
        static byte mul_by_02( byte num )
        {
            byte res;
            if (num < 0x80)
            {
                res = (byte)(num << 1);
            }
            else
            {
                res = (byte)((num << 1) ^ 0x1b);
            }
            return (byte)(res % 0x100);
        }

        static byte mul_by_03(byte num)
        {
            return (byte)(mul_by_02(num) ^ num);
        }

        static byte mul_by_09(byte num)
        {
            return (byte)( mul_by_02( (byte)(mul_by_02( (byte)(mul_by_02(num)) )) ) ^ num );
        }

        static byte mul_by_0b(byte num) {
            return (byte)( mul_by_02( (byte)(mul_by_02(mul_by_02(num)) ) ) ^ (byte)(mul_by_02(num)) ^ num);
        }

        static byte mul_by_0d(byte num){
            return (byte)(mul_by_02((byte)(mul_by_02((byte)(mul_by_02(num))))) ^ (byte)(mul_by_02((byte)(mul_by_02(num)))) ^ num);
        }

        static byte mul_by_0e(byte num){
            return (byte)(mul_by_02((byte)(mul_by_02((byte)(mul_by_02(num))))) ^ mul_by_02((byte)(mul_by_02(num))) ^ (byte)(mul_by_02(num)));
        }
        //------------------------------------------------------------------------end definition of additional functions



        //--------------------------- Decryption --------------------------------

        static void InvCipher(byte[,] state, byte[] key)
        {
            byte round;
            byte[,] KeyShedule = new byte[4, Nb * (Nr + 1)];

            KeyExpansion( KeyShedule, key );


            AddRoundKey(Nr, state, KeyShedule);

            for (round = (byte)(Nr-1); round > 0; round--)
            {
                InvShiftRows(state);
                InvSubBytes(state);
                AddRoundKey(round, state, KeyShedule);
                InvMixColumns(state);
            }

            InvShiftRows(state);
            InvSubBytes(state);
            AddRoundKey(0, state, KeyShedule);
        }
        
        
        // The InvSubBytes Function Substitutes the values in the
        // state matrix with values in an InvSbox
        static void InvSubBytes(byte[,] state)
        {
            for (byte col = 0; col < Nb; ++col)
            {
                state[0, col] = Boxes.getInvSBoxValue(state[0, col]);
                state[1, col] = Boxes.getInvSBoxValue(state[1, col]);
                state[2, col] = Boxes.getInvSBoxValue(state[2, col]);
                state[3, col] = Boxes.getInvSBoxValue(state[3, col]);
            }
        }//end SubBytes()

        static void InvShiftRows(byte[,] state)
        {
            byte temp;

            // Rotate first row 1 columns to right  
            temp = state[1, 3];
            state[1, 3] = state[1, 2];
            state[1, 2] = state[1, 1];
            state[1, 1] = state[1, 0];
            state[1, 0] = temp;

            // Rotate second row 2 columns to right 
            temp = state[2, 0];
            state[2, 0] = state[2, 2];
            state[2, 2] = temp;

            temp = state[2, 1];
            state[2, 1] = state[2, 3];
            state[2, 3] = temp;

            // Rotate third row 3 columns to right
            temp = state[3, 0];
            state[3, 0] = state[3, 1];
            state[3, 1] = state[3, 2];
            state[3, 2] = state[3, 3];
            state[3, 3] = temp;
        }

        // InvMixColumns function mixes the columns of the state matrix
        static void InvMixColumns(byte[,] state)
        {
            byte i;
            for (i = 0; i < Nb; ++i)
            {
                 byte s0 = (byte)(mul_by_0e(state[0, i])^mul_by_0b(state[1, i])^mul_by_0d(state[2, i])^mul_by_09(state[3, i]));
                 byte s1 = (byte)(mul_by_09(state[0, i])^mul_by_0e(state[1, i])^mul_by_0b(state[2, i])^mul_by_0d(state[3, i]));
                 byte s2 = (byte)(mul_by_0d(state[0, i])^mul_by_09(state[1, i])^mul_by_0e(state[2, i])^mul_by_0b(state[3, i]));
                 byte s3 = (byte)(mul_by_0b(state[0, i]) ^ mul_by_0d(state[1, i]) ^ mul_by_09(state[2, i]) ^ mul_by_0e(state[3, i]));

                state[0, i] = s0;
                state[1, i] = s1;
                state[2, i] = s2;
                state[3, i] = s3;
            }
        }

        //--------------------------------------------------------------------
        //-------------------------------------------------------------------- 
    }
}
