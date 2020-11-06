# SIP2
Library SIP2 C# .net standard 2.0
add sip2.dll to project
example fro C#

...
using SIP2;
...
private void btmPatronInfrmation_Click(object sender, EventArgs e)
{
            SIP2.SIP2 SIP2_Control=new SIP2.SIP2(); 
            SIP2_Control.SipConnection(IP, Port, User, Password, extra_number);
            SIP2_Control.Open();

            SIP2_Control.setPatron(txtPatron.Text);
            SIP2_Control.setPatronpwd(txtPassword.Text);
            //MessageBox.Show(SIP2_Control.msgPatronInformation("all"));
                        
            IDictionary<string, IDictionary<string, string>> return_value = SIP2_Control.parsePatronInfoResponse(SIP2_Control.msgPatronInformation("all"));

            if (return_value["fixed"]["PatronStatus"] == "              ")
            {
                SIP2_Control.setPatronpwd("");
                txtDetail.Text = "";
                txtDetail.Text += "Barcode\t:\t " + return_value["variable"]["AA"]+"\r\n";
                txtDetail.Text += "Title\t:\t" + return_value["variable"]["AE"] + "\r\n";
                txtDetail.Text += "Resource\r\n";

                string[] words = return_value["variable"]["AU"].ToString().Split('|');
                int wLen = words.Length;

                string Barcode;
                string[] Title;

                for (int i = 0; i <= wLen - 1; i++)
                {
                    Barcode = words[i].Substring(8, 14);
                    Title = words[i].Substring(29).Split('/');

                    txtDetail.Text += (i+1).ToString() +". Barcode : " + Barcode + "\r\n";
                    txtDetail.Text += "   Title : " + Title[0].Trim() + "\r\n";
                    txtDetail.Text += "   Author : " + Title[1].Trim() + "\r\n";
                }
            }
            else
            {
                MessageBox.Show("User or Password Failed");
            }

            SIP2_Control.Close();

}
