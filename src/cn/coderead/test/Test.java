package cn.coderead.test;


import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.atomic.LongAdder;

/**
 * <p>描述:
 * <p>日期: 2021/3/18 16:33
 * <p>作者: cws
 */
public class Test {
    public static void main(String[] args) {
        ForkJoinPool fjp = new ForkJoinPool();
        fjp.execute(()-> System.out.println("hello world!"));
    }
}
