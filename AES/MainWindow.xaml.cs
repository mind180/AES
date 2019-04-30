using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.IO;
using System.Security.Cryptography;
using Microsoft.Win32;

namespace AES
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        string uncrypted = "";
        byte[] encrypted;
        String path = "";
        string res = "";

        //--------------------------------- main and events ---------------------
        public MainWindow()
        {
            InitializeComponent();
                   
        }

        private byte[] getKey(String keyWord)
        {
            int keySize = 0;

            if (Aes.getNk() == 4)
                keySize = 16;
            else if (Aes.getNk() == 6)
                keySize = 24;
            else if (Aes.getNk() == 8)
                keySize = 32;

            byte[] key = new byte [keySize];

            for (int i = 0; i < key.Count(); i++)
                key[i] = 0x1;

            for (int i = 0; i < keyWord.Count() && i < key.Count(); i++)
                key[i] = Convert.ToByte( keyWord[i] );
            
            return key;
        }

        private static readonly byte[] Salt = new byte[] { 10, 20, 30, 40, 50, 60, 70, 80 };

        public static byte[] CreateKey(string password, int keyBytes)
        {
            const int Iterations = 300;
            var keyGenerator = new Rfc2898DeriveBytes(password, Salt, Iterations);
            return keyGenerator.GetBytes(keyBytes);
        }

        private void ButtonOpen_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog fileDialog = new OpenFileDialog();
            if ( fileDialog.ShowDialog() == true )
            {
                path = fileDialog.FileName;  
            }

            Path.Text = path;

            try
            {
                using ( FileStream fs = File.Open(path, FileMode.Open) )
                {
                    byte[] data = new byte[102400];
                    int len = fs.Read(data, 0, data.Length);

                    char[] dataChar = new char[len];

                    for (int i = 0; i < len; i++)
                    {
                        dataChar[i] = Convert.ToChar(data[i]);
                    }

                    uncrypted = new String(dataChar);

                    Source.Text = "File Size: " + uncrypted.Length.ToString() + "\n";
                    Source.Text += uncrypted;

                    //output encoded

                    Execute.IsEnabled = true;
                }
            }
            catch (FileNotFoundException)
            {
                Path.Text = "File not found!";
            }
            catch (ArgumentException)
            {
                Path.Text = "Path is empty!";
            }
            catch (DirectoryNotFoundException)
            {
                Path.Text = "Directory not found!";
            }
                  
            

        }

        private void ButtonExecute_Click(object sender, RoutedEventArgs e)
        {
            Encrypted.Text = "";
            Info.Text = "";

            int keySize = 16;
            if (Key.Text == "")
            {
                Key.Text = "Key can`t be empty!!!";
                return;
            }

            if ((bool)Aes128.IsChecked)
            {
                Aes.setNk(4);
            }
            else if ((bool)Aes192.IsChecked)
            {
                Aes.setNk(6);
                keySize = 24;
            }
            else if ((bool)Aes256.IsChecked)
            {
                Aes.setNk(8);
                keySize = 32;
            }

            byte[] key = CreateKey(Key.Text, keySize);

            //-------------------------------------------------------------------

            byte[] buff = new byte[uncrypted.Length];

            char[] c = uncrypted.ToArray();

            for (int i = 0; i < c.Count(); i++)
                buff[i] = Convert.ToByte(c[i]);

            if ((bool)REncrypt.IsChecked)
            {
                if ((bool)Report.IsChecked)
                {
                    WaitWindow ww = new WaitWindow();
                    ww.Show();
                    encrypted = Aes.Encrypt(buff, key, ref res);
                    Info.Text = res;
                    ww.Close();

                    
                }
                else
                {
                    encrypted = Aes.Encrypt(buff, key);
                }

                //Encrypted field
                char[] buff2 = new char[encrypted.Length];
                string bufEnc = "";

                for (int i = 0; i < encrypted.Count(); i++)
                {
                    char ch = Convert.ToChar(encrypted[i]);
                    bufEnc += Convert.ToString(ch);
                }

                Encrypted.Text += bufEnc;

                if ((bool)Save.IsChecked)
                {
                    String path = Path.Text;
                    path += ".enc";
                    //---------------------------------write in file--------------------------------
                    try
                    {
                        using (FileStream fs = File.Open(path, FileMode.OpenOrCreate, FileAccess.Write, FileShare.None))
                        {
                            fs.Write(encrypted, 0, encrypted.Count());
                            MessageBox.Show("Write success \n" + path);
                        }
                    }
                    catch (SystemException)
                    {
                        throw new SystemException();
                    }
                }


            }
            else if ((bool)RDecrypt.IsChecked)
            {
                try
                {
                    using (FileStream fs = File.Open(path, FileMode.Open))
                    {
                        int snipped = 0;
                        byte[] data = new byte[102400];
                        int len = fs.Read(data, 0, data.Length);


                        // ------copy needed info from buffer----
                        byte[] temp = new byte[len];
                        for (int i = 0; i < len; i++)
                            temp[i] = data[i];
                        //----------------------------------------


                        //decrypton
                        byte[] decrypted = Aes.Decrypt(temp, key);

                        // find last block
                        if (data[len - 16] == 0x1)
                        {
                            snipped = decrypted[decrypted.Count() - 17];
                            if (snipped > 16) snipped = 16;
                        }
                        else
                        {
                            snipped = 0;
                        }
                        //---------------------------------------


                        char[] dataChar = new char[(decrypted.Count() - 32) + snipped];

                        for (int i = 0; i < dataChar.Count(); i++)
                        {
                            dataChar[i] = Convert.ToChar(decrypted[i]);
                        }

                        uncrypted = new String(dataChar);

                        Source.Text = "File Size: " + uncrypted.Length.ToString() + "\n";
                        Source.Text += uncrypted;

                        //output encoded                        
                    }
                }
                catch (FileNotFoundException)
                {
                    Path.Text = "File not found!";
                }
                catch (ArgumentException)
                {
                    Path.Text = "Path is empty!";
                }
                catch (DirectoryNotFoundException)
                {
                    Path.Text = "Directory not found!";
                }            }

        }

        private void REncrypt_Checked(object sender, RoutedEventArgs e)
        {

        }

        private void RDecrypt_Checked(object sender, RoutedEventArgs e)
        {

        }


        
       

        //private void ButtonEncrypt_Click(object sender, RoutedEventArgs e)
        //{
        //    if (KeyField.Text == "")
        //    {
        //        KeyField.Text = "Key can`t be empty!!!";
        //        return;
        //    }
                                  

        //    // --------------------------key size --------------------------------
        //    int keySize = 16;
        //    if (KeySizeField.SelectedIndex == 0)
        //    {
        //        MessageBox.Show("Choose key size");
        //        return;
        //    }
        //    else if (KeySizeField.SelectedIndex == 1)
        //    {
        //        Aes.setNk(4);
        //    }
        //    else if (KeySizeField.SelectedIndex == 2)
        //    {
        //        Aes.setNk(6);
        //        keySize = 24;
        //    }
        //    else if (KeySizeField.SelectedIndex == 3)
        //    {
        //        Aes.setNk(8);
        //        keySize = 32;
        //    }
        //    //---------------------------------------------------------------------

        //    //byte[] key = getKey(KeyField.Text);
        //    byte[] key = CreateKey(KeyField.Text, keySize);



        //    byte[] buff = new byte[uncrypted.Length];

        //    char[] c = uncrypted.ToArray();

        //    for (int i = 0; i < c.Count(); i++)
        //        buff[i] = Convert.ToByte(c[i]);

        //    String res = "";

        //    encrypted = Aes.Encrypt( buff, key, ref res );

        //    TextEncrypt.Text = res;

        //    //---------------------------------------------------------------------

        //    //char[] buff2 = new char[encrypted.Length];
        //    string buff2 = "";

        //    for (int i = 0; i < encrypted.Count(); i++)
        //    {
        //        char ch = Convert.ToChar(encrypted[i]);
        //        buff2 += Convert.ToString(ch);
        //    }



        //    TextEncrypt.Text += buff2.ToString();
        //    ButtonSave.IsEnabled = true;
        //}

        //private void ButtonDecode_Click(object sender, RoutedEventArgs e)
        //{
        //    String path = TextBoxPath.Text;

        //    int keySize = 16;
        //    if (KeySizeDecode.SelectedIndex == 0)
        //    {
        //        MessageBox.Show("Choose key size");
        //        return;
        //    }
        //    else if (KeySizeDecode.SelectedIndex == 1)
        //    {
        //        Aes.setNk(4);
        //    }
        //    else if (KeySizeDecode.SelectedIndex == 2)
        //    {
        //        Aes.setNk(6);
        //        keySize = 24;
        //    }
        //    else if (KeySizeDecode.SelectedIndex == 3)
        //    {
        //        Aes.setNk(8);
        //        keySize = 32;
        //    }

        //    //byte[] key = getKey(TextBoxKey.Text);
            
        //    byte[] key = CreateKey(TextBoxKey.Text, keySize);

        //    try
        //    {
        //        using ( FileStream fs = File.Open(path, FileMode.Open) )
        //        {
        //            int snipped = 0;
        //            byte[] data = new byte[102400];
        //            int len = fs.Read(data, 0, data.Length);

                   
        //            // ------copy needed info from buffer----
        //            byte[] temp = new byte[len];
        //            for (int i = 0; i < len; i++)
        //                temp[i] = data[i];
        //            //----------------------------------------


        //            //decrypton
        //            byte[] decrypted = Aes.Decrypt(temp, key);

        //            // find last block
        //            if (data[len - 16] == 0x1)
        //            {
        //                snipped = decrypted[decrypted.Count() - 17];
        //                if (snipped > 16) snipped = 16;
        //            }
        //            else
        //            {
        //                snipped = 0;
        //            }
        //            //---------------------------------------
                    
                    
        //            char[] dataChar = new char[ (decrypted.Count()- 32)+snipped ];

        //            for ( int i = 0; i < dataChar.Count(); i++ )
        //            {
        //                dataChar[i] = Convert.ToChar( decrypted[i] );
        //            }

        //            uncrypted = new String(dataChar);
                                        
        //            TextField.Text = "File Size: " + uncrypted.Length.ToString() + "\n";
        //            TextField.Text += uncrypted;
                                        
        //            //output encoded

        //            Encrypt.IsEnabled = true;
        //        }
        //    }
        //    catch (FileNotFoundException)
        //    {
        //        TextBoxPath.Text = "File not found!";
        //    }
        //    catch (ArgumentException)
        //    {
        //        TextBoxPath.Text = "Path is empty!";
        //    }
        //    catch (DirectoryNotFoundException)
        //    {
        //        TextBoxPath.Text = "Directory not found!";
        //    }


        //}

        //private void ButtonSave_Click(object sender, RoutedEventArgs e)
        //{
        //    String path = TextBoxSave.Text;

        //    //---------------------------------write in file--------------------------------
        //    try
        //    {
        //        using ( FileStream fs = File.Open(path, FileMode.OpenOrCreate, FileAccess.Write, FileShare.None) ) 
        //        {
        //            fs.Write(encrypted, 0, encrypted.Count());
        //            MessageBox.Show("Write success");
        //        }
        //    }
        //    catch (SystemException)
        //    {
        //        throw new SystemException();
        //    }
        //}

        //private void ButtonOpen_Click( object sender, RoutedEventArgs e )
        //{
        //    String path = TextBoxPath.Text;

        //    try
        //    {
        //        using (FileStream fs = File.Open(path, FileMode.Open))
        //        {
        //            byte[] data = new byte[102400];
        //            int len = fs.Read(data, 0, data.Length);

        //            char[] dataChar = new char[len];

        //            for (int i = 0; i < len; i++)
        //            {
        //                dataChar[i] = Convert.ToChar(data[i]);
        //            }

        //            uncrypted = new String(dataChar);

        //            TextField.Text = "File Size: " + uncrypted.Length.ToString() + "\n";
        //            TextField.Text += uncrypted;

        //            //output encoded

        //            Encrypt.IsEnabled = true;
        //        }
        //    }
        //    catch (FileNotFoundException)
        //    {
        //        TextBoxPath.Text = "File not found!";
        //    }
        //    catch (ArgumentException)
        //    {
        //        TextBoxPath.Text = "Path is empty!";
        //    }
        //    catch (DirectoryNotFoundException)
        //    {
        //        TextBoxPath.Text = "Directory not found!";
        //    }
                        
          
        //}

      
        //-----------------------------------------------------------------------
    }

}
