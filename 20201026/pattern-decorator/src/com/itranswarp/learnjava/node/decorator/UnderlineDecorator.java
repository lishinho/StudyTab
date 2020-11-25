package com.itranswarp.learnjava.node.decorator;

import com.itranswarp.learnjava.node.NodeDecorator;
import com.itranswarp.learnjava.node.TextNode;

public class UnderlineDecorator extends NodeDecorator {

	public UnderlineDecorator(TextNode target) {
		super(target);
	}

	@Override
	public String getText() {
		return "<u>" + target.getText() + "</u>";
	}
}
