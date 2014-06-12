import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JTextArea;

public class Main extends JFrame {
	private int type = 0;// 1 aes,2 sms4;
	public JPanel pnMain;
	public JPanel pnBtn1;
	public JPanel pnChoice;
	public JLabel jlbKey;
	public JLabel jlbContent;
	public JLabel jlbSecret;
	public JTextArea txtKey;
	public JTextArea txtContent;
	public JTextArea txtSecret;
	public JButton btnEncrypt;
	public JButton btnDecrypt;
	public JRadioButton jrbtnAES;
	public JRadioButton jrbtnSMS4;

	public Main() {
		pnMain = new JPanel();
		pnBtn1 = new JPanel(new FlowLayout());
		pnChoice = new JPanel(new FlowLayout());
		jlbKey = new JLabel();
		jlbContent = new JLabel();
		jlbSecret = new JLabel();
		txtKey = new JTextArea(5, 5);
		txtContent = new JTextArea(5, 5);
		txtSecret = new JTextArea(5, 5);
		txtKey.setLineWrap(true);
		txtContent.setLineWrap(true);
		txtSecret.setLineWrap(true);
		btnEncrypt = new JButton();
		btnDecrypt = new JButton();
		jrbtnAES = new JRadioButton();
		jrbtnSMS4 = new JRadioButton();
		userInit();
	}

	public void userInit() {
		txtKey.setText("buzhidao");
		txtContent.setText("abcdabcdabcdabcd");
		this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);// 设置关闭框架的同时结束程序
		this.setSize(500, 500);// 设置框架大小为长300,宽200
		this.setTitle("AES&&SMS4加密测试");// 设置框架标题
		this.pnMain.setLayout(new GridLayout(10, 1));// 设置面板布局管理
		this.jlbKey.setText("秘钥:");
		this.jlbSecret.setText("密文:");
		this.jlbContent.setText("明文:");
		this.btnEncrypt.setText("加密");
		this.btnDecrypt.setText("解密");
		jrbtnAES.setText("AES");
		jrbtnSMS4.setText("SMS4");
		pnChoice.add(jrbtnAES);
		pnChoice.add(jrbtnSMS4);
		ButtonGroup group = new ButtonGroup();
		group.add(jrbtnAES);
		group.add(jrbtnSMS4);
		pnMain.add(pnChoice);
		pnMain.add(jlbKey);
		pnMain.add(txtKey);
		pnMain.add(jlbContent);
		pnMain.add(txtContent);
		pnMain.add(jlbSecret);
		pnMain.add(txtSecret);
		pnBtn1.add(btnEncrypt);
		pnBtn1.add(btnDecrypt);
		pnMain.add(pnBtn1);
		jrbtnAES.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				// TODO Auto-generated method stub
				JRadioButton radio = (JRadioButton) e.getSource();
				if (radio == jrbtnAES) {
					type = 1;
				}
			}
		});
		jrbtnSMS4.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				// TODO Auto-generated method stub
				JRadioButton radio = (JRadioButton) e.getSource();
				if (radio == jrbtnSMS4) {
					type = 2;
				}
			}
		});
		this.btnEncrypt.addActionListener(new ActionListener()// 匿名类实现ActionListener接口
				{
					public void actionPerformed(ActionEvent e) {
						btnEncrypt_ActionEvent(e);
					}
				});
		this.btnDecrypt.addActionListener(new ActionListener()// 匿名类实现ActionListener接口
				{
					public void actionPerformed(ActionEvent e) {
						btnDecrypt_ActionEvent(e);
					}
				});
		this.setContentPane(pnMain);
		this.setVisible(true);// 设置框架可显
	}

	public void btnEncrypt_ActionEvent(ActionEvent e) {
		String content = txtContent.getText();
		String key = txtKey.getText();
		if (content.equals("")) {
			JOptionPane.showMessageDialog(null, "明文不能为空", "错误",
					JOptionPane.ERROR_MESSAGE);
			return;
		}
		if (content.length()%16!=0) {
			JOptionPane.showMessageDialog(null, "密文长度需为128bit的倍数，否则会出现加密错误", "错误",
					JOptionPane.ERROR_MESSAGE);
			return;
		}
		if (type == 0) {
			JOptionPane.showMessageDialog(null, "请先选择加密类型", "错误",
					JOptionPane.ERROR_MESSAGE);
			return;
		} else if (type == 1) {
			AES aes;
			try {
				aes = new AES(getRawKey(key.getBytes()));
				byte[] encryptResult = aes.encrypt(content.getBytes());
				String encryptResultStr = parseByte2HexStr(encryptResult);
				txtSecret.setText(encryptResultStr);
				// System.out.println(new String(key));
				// System.out.println(new String(content));
				// System.out.println("加密后原始数组:");
				// aes.print(encryptResult);
				// System.out.println("加密后：" + encryptResultStr);
				// System.out.println("解密后：" + new
				// String(aes.decrypt(encryptResult)));
			} catch (Exception e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		} else if (type == 2) {
			SMS4 sms4;
			try {
				sms4 = new SMS4(getRawKey(key.getBytes()));
				byte[] encryptResult = sms4.encrypt(content.getBytes());
				String encryptResultStr = parseByte2HexStr(encryptResult);
				txtSecret.setText(encryptResultStr);
			} catch (Exception e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		}
	}

	public void btnDecrypt_ActionEvent(ActionEvent e) {
		String content = txtSecret.getText();
		String key = txtKey.getText();
		if (content.equals("")) {
			JOptionPane.showMessageDialog(null, "密文不能为空", "错误",
					JOptionPane.ERROR_MESSAGE);
			return;
		}
		if (type == 0) {
			JOptionPane.showMessageDialog(null, "请先选择加密类型", "错误",
					JOptionPane.ERROR_MESSAGE);
			return;
		} else if (type == 1) {
			AES aes;
			try {
				aes = new AES(getRawKey(key.getBytes()));
				byte[] encryptResult = aes.decrypt(parseHexStr2Byte(content));
				String encryptResultStr =new String(encryptResult);
				txtContent.setText(encryptResultStr);
			} catch (Exception e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		} else if (type == 2) {
			SMS4 sms4;
			try {
				sms4 = new SMS4(getRawKey(key.getBytes()));
				byte[] encryptResult = sms4.decrypt(parseHexStr2Byte(content));
				String encryptResultStr = new String(encryptResult);
				txtContent.setText(encryptResultStr);
			} catch (Exception e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		}
	}

	public static void main(String[] args) {
		new Main();
	}

	private static byte[] getRawKey(byte[] seed) throws Exception {
		KeyGenerator kgen = KeyGenerator.getInstance("AES");
		SecureRandom sr = null;
		sr = SecureRandom.getInstance("SHA1PRNG");
		sr.setSeed(seed);
		kgen.init(128, sr); // 192 and 256 bits may not be available
		SecretKey skey = kgen.generateKey();
		byte[] raw = skey.getEncoded();
		return raw;
	}

	public static String parseByte2HexStr(byte buf[]) {
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < buf.length; i++) {
			String hex = Integer.toHexString(buf[i] & 0xFF);
			if (hex.length() == 1) {
				hex = '0' + hex;
			}
			sb.append(hex.toUpperCase());
		}
		return sb.toString();
	}

	public static byte[] parseHexStr2Byte(String hexStr) {
		if (hexStr.length() < 1)
			return null;
		byte[] result = new byte[hexStr.length() / 2];
		for (int i = 0; i < hexStr.length() / 2; i++) {
			int high = Integer.parseInt(hexStr.substring(i * 2, i * 2 + 1), 16);
			int low = Integer.parseInt(hexStr.substring(i * 2 + 1, i * 2 + 2),
					16);
			result[i] = (byte) (high * 16 + low);
		}
		return result;
	}
	public static byte[] toByte(String hexString) {
		int len = hexString.length() / 2;
		byte[] result = new byte[len];
		for (int i = 0; i < len; i++)
			result[i] = Integer.valueOf(hexString.substring(2 * i, 2 * i + 2),
					16).byteValue();
		return result;
	}
}