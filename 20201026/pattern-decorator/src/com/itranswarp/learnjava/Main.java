package com.itranswarp.learnjava;

import java.io.IOException;

import com.itranswarp.learnjava.node.SpanNode;
import com.itranswarp.learnjava.node.TextNode;
import com.itranswarp.learnjava.node.decorator.BoldDecorator;
import com.itranswarp.learnjava.node.decorator.ItalicDecorator;
import com.itranswarp.learnjava.node.decorator.UnderlineDecorator;

/**
 * Learn Java from https://www.liaoxuefeng.com/
 * 
 * @author liaoxuefeng
 */
public class Main {

	public static void main(String[] args) throws IOException {
		TextNode n1 = new SpanNode();
		TextNode n2 = new BoldDecorator(new UnderlineDecorator(new SpanNode()));
		TextNode n3 = new ItalicDecorator(new BoldDecorator(new SpanNode()));
		n1.setText("Hello");
		n2.setText("Decorated");
		n3.setText("World");
		System.out.println(n1.getText());
		System.out.println(n2.getText());
		System.out.println(n3.getText());
	}
}
