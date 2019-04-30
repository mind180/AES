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
using System.Windows.Shapes;
using System.IO;

namespace AES
{
    
    /// <summary>
    /// Interaction logic for WindowOpen.xaml
    /// </summary>
    public partial class WindowOpen : Window
    {
        String uncrypted = "";
        public WindowOpen()
        {
            InitializeComponent();
        }


        
        private void ButtonOpen_Click(object sender, RoutedEventArgs e)
        {
            String path = TextBoxPath.Text;

            try
            {
                using (FileStream fs = File.Open(path, FileMode.Open))
                {
                    byte[] data = new byte[102400];
                    int len = fs.Read(data, 0, data.Length);

                    char[] dataChar = new char[len];

                    for (int i = 0; i < len; i++)
                    {
                        dataChar[i] = Convert.ToChar(data[i]);
                    }

                    uncrypted = new String(dataChar);

                    TextField.Text = "File Size: " + uncrypted.Length.ToString() + "\n";
                    TextField.Text += uncrypted;

                    //output encoded

                    Encrypt.IsEnabled = true;
                }
            }
            catch (FileNotFoundException)
            {
                TextBoxPath.Text = "File not found!";
            }
            catch (ArgumentException)
            {
                TextBoxPath.Text = "Path is empty!";
            }
            catch (DirectoryNotFoundException)
            {
                TextBoxPath.Text = "Directory not found!";
            }
        }

      
        private void Encrypt_Click( object sender, RoutedEventArgs e )
        {
            String key = KeyField.Text;
            
           

            if ( KeySizeField.SelectedIndex == 0 )
            {
                MessageBox.Show("Choose key size");
                return;
            }
            else if (KeySizeField.SelectedIndex == 1)
            {
                Aes.setNk(4);
            }
            else if (KeySizeField.SelectedIndex == 2)
            {
                Aes.setNk(6);
            }
            else if (KeySizeField.SelectedIndex == 3)
            {
                Aes.setNk(8);
            }
                       
            
            this.Close();

        }

    }
}
