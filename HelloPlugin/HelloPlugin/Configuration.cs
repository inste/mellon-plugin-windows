using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;

namespace pGina.Plugin.Mellon
{
    
    public partial class Configuration : Form
    {
        public Configuration()
        {
            InitializeComponent();
            textBox1.Text = PluginImpl.Settings.ServerHostName.ToString();
            textBox2.Text = PluginImpl.Settings.PubKeyName.ToString();
            textBox3.Text = PluginImpl.Settings.PrivKeyName.ToString();
            numericUpDown1.Value = Convert.ToInt32(PluginImpl.Settings.ServerPort.ToString());
        }

        private void button1_Click(object sender, EventArgs e)
        {
            //!!FIXME!! Check entered values
            PluginImpl.Settings.ServerHostName = textBox1.Text;
            PluginImpl.Settings.PubKeyName = textBox2.Text;
            PluginImpl.Settings.PrivKeyName = textBox3.Text;
            PluginImpl.Settings.ServerPort = numericUpDown1.Value;
            this.Close();
        }



        
    }
}
