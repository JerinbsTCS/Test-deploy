package com.example.idor;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import com.example.idor.entity.Customer;
import com.example.idor.entity.Invoice;
import com.example.idor.entity.Order;
import com.example.idor.entity.WishlistItem;
import com.example.idor.repository.CustomerRepository;
import com.example.idor.repository.InvoiceRepository;
import com.example.idor.repository.OrderRepository;
import com.example.idor.repository.WishlistRepository;

@Component
public class DataSeeder implements ApplicationRunner {

    private final CustomerRepository customerRepo;
    private final OrderRepository orderRepo;
    private final InvoiceRepository invoiceRepo;
    private final WishlistRepository wishlistRepo;
    private final String ctfFlag;

    public DataSeeder(CustomerRepository customerRepo,
                      OrderRepository orderRepo,
                      InvoiceRepository invoiceRepo,
                      WishlistRepository wishlistRepo,
                      @Value("${app.ctf-flag}") String ctfFlag) {
        this.customerRepo = customerRepo;
        this.orderRepo = orderRepo;
        this.invoiceRepo = invoiceRepo;
        this.wishlistRepo = wishlistRepo;
        this.ctfFlag = ctfFlag;
    }

    @Override
    public void run(ApplicationArguments args) {
        // ── Customers ─────────────────────────────────────────────────────
        Customer john = createCustomer("john", "John Peterson",
                "john.peterson@gmail.com", "+1-555-0101",
                "742 Evergreen Terrace, Apt 3B", "Springfield", "62704", "CUSTOMER");

        Customer sarah = createCustomer("sarah", "Sarah Mitchell",
                "sarah.mitchell@outlook.com", "+1-555-0102",
                "1600 Pennsylvania Ave NW", "Washington", "20500", "CUSTOMER");

        Customer mike = createCustomer("mike", "Mike Chen",
                "mike.chen@yahoo.com", "+1-555-0103",
                "350 Fifth Avenue, Suite 3400", "New York", "10118", "CUSTOMER");

        Customer emma = createCustomer("emma", "Emma Williams",
                "emma.w@protonmail.com", "+1-555-0104",
                "221B Baker Street", "London", "NW1 6XE", "CUSTOMER");

        Customer support = createCustomer("support", "Support Agent",
                "support@shopez.com", "+1-555-0200",
                "ShopEZ HQ, 100 Commerce Blvd", "Austin", "73301", "SUPPORT");

        Customer admin = createCustomer("admin", "Admin User",
                "admin@shopez.com", "+1-555-0300",
                "ShopEZ HQ, 100 Commerce Blvd", "Austin", "73301", "ADMIN");

        // ── Orders & Invoices ─────────────────────────────────────────────

        // John (id=1) — Electronics buyer
        Order o1 = createOrder(john.getId(), "2026-04-10", "DELIVERED", 1299.99,
                "MacBook Air M3 (1x $1,299.99)", "1Z999AA10123456784",
                "742 Evergreen Terrace, Apt 3B, Springfield, IL 62704");
        createInvoice(john.getId(), o1.getId(), "2026-04-10", 1299.99, 104.00, 1403.99,
                "VISA ending 4242", "742 Evergreen Terrace, Springfield, IL", "PAID", "4242");

        Order o2 = createOrder(john.getId(), "2026-04-28", "SHIPPED", 249.99,
                "Sony WH-1000XM5 Headphones (1x $249.99)", "1Z999AA10123456799",
                "742 Evergreen Terrace, Apt 3B, Springfield, IL 62704");
        createInvoice(john.getId(), o2.getId(), "2026-04-28", 249.99, 20.00, 269.99,
                "VISA ending 4242", "742 Evergreen Terrace, Springfield, IL", "PAID", "4242");

        // Sarah (id=2) — Fashion & luxury buyer (high-value orders)
        Order o3 = createOrder(sarah.getId(), "2026-03-22", "DELIVERED", 3450.00,
                "Louis Vuitton Neverfull MM (1x $2,300.00), Hermès Silk Scarf (1x $1,150.00)",
                "1Z999BB20234567890",
                "1600 Pennsylvania Ave NW, Washington, DC 20500");
        createInvoice(sarah.getId(), o3.getId(), "2026-03-22", 3450.00, 276.00, 3726.00,
                "AMEX ending 1001", "1600 Pennsylvania Ave NW, Washington, DC", "PAID", "1001");

        Order o4 = createOrder(sarah.getId(), "2026-05-01", "PENDING", 890.00,
                "Dyson Airwrap (1x $599.99), La Mer Moisturizer (1x $290.01)",
                null,
                "1600 Pennsylvania Ave NW, Washington, DC 20500");
        createInvoice(sarah.getId(), o4.getId(), "2026-05-01", 890.00, 71.20, 961.20,
                "AMEX ending 1001", "1600 Pennsylvania Ave NW, Washington, DC", "PENDING", "1001");

        // Mike (id=3) — Corporate buyer (sensitive B2B orders)
        Order o5 = createOrder(mike.getId(), "2026-04-15", "DELIVERED", 15750.00,
                "Dell PowerEdge R760 Server (1x $12,500.00), Cisco Catalyst 9300 Switch (1x $3,250.00)",
                "1Z999CC30345678901",
                "350 Fifth Avenue, Suite 3400, New York, NY 10118");
        createInvoice(mike.getId(), o5.getId(), "2026-04-15", 15750.00, 1398.75, 17148.75,
                "Corporate PO #NYC-2026-0892", "350 Fifth Ave, New York, NY", "PAID", "8834");

        Order o6 = createOrder(mike.getId(), "2026-04-30", "SHIPPED", 4200.00,
                "50x Logitech MX Master 3S Mouse ($84.00 each)",
                "1Z999CC30345678922",
                "350 Fifth Avenue, Suite 3400, New York, NY 10118");
        createInvoice(mike.getId(), o6.getId(), "2026-04-30", 4200.00, 373.80, 4573.80,
                "Corporate PO #NYC-2026-0915", "350 Fifth Ave, New York, NY", "PENDING", "8834");

        // Emma (id=4) — Gift buyer (shipping to others = juicy addresses)
        Order o7 = createOrder(emma.getId(), "2026-04-20", "DELIVERED", 189.99,
                "Nintendo Switch OLED (1x $189.99 — GIFT)", "1Z999DD40456789012",
                "GIFT TO: Tom Williams, 45 Maple Drive, Bristol, BS1 4DJ");
        createInvoice(emma.getId(), o7.getId(), "2026-04-20", 189.99, 15.20, 205.19,
                "PayPal (emma.w@protonmail.com)", "221B Baker Street, London", "PAID", null);

        Order o8 = createOrder(emma.getId(), "2026-05-03", "PENDING", 524.97,
                "Kindle Paperwhite (1x $149.99), AirPods Pro 2 (1x $249.99), Gift Card $125 (1x $124.99)",
                null,
                "GIFT TO: Sophie Williams, 12 Rose Lane, Manchester, M1 2AB");
        createInvoice(emma.getId(), o8.getId(), "2026-05-03", 524.97, 42.00, 566.97,
                "PayPal (emma.w@protonmail.com)", "221B Baker Street, London", "PENDING", null);

        // Admin (id=6) — Contains the CTF flag
        Order o9 = createOrder(admin.getId(), "2026-05-05", "DELIVERED", 0.00,
                ctfFlag, "INTERNAL-CTF-001",
                "ShopEZ HQ, 100 Commerce Blvd, Austin, TX 73301");
        createInvoice(admin.getId(), o9.getId(), "2026-05-05", 0.00, 0.00, 0.00,
                "INTERNAL", "ShopEZ HQ", "PAID", null);

        // ── Wishlists ─────────────────────────────────────────────────────

        createWishlist(john.getId(), "PS5 Pro", 499.99, "2026-04-01", "For Christmas");
        createWishlist(john.getId(), "LG C4 65\" OLED TV", 1799.99, "2026-04-15", null);

        createWishlist(sarah.getId(), "Chanel Classic Flap Bag", 8800.00, "2026-03-10", "Birthday gift to self");
        createWishlist(sarah.getId(), "Cartier Love Bracelet", 6900.00, "2026-04-02", "Anniversary");

        createWishlist(mike.getId(), "Standing Desk - Uplift V2", 599.00, "2026-04-20", "For home office");
        createWishlist(mike.getId(), "Herman Miller Aeron Chair", 1395.00, "2026-04-25", "Expense to company");

        createWishlist(emma.getId(), "Lego Millennium Falcon", 849.99, "2026-05-01", "Gift for Dad's birthday");
        createWishlist(emma.getId(), "KitchenAid Stand Mixer", 379.99, "2026-05-02", "Mum's anniversary");
    }

    private Customer createCustomer(String username, String fullName, String email,
                                    String phone, String address, String city,
                                    String zip, String role) {
        Customer c = new Customer();
        c.setUsername(username);
        c.setFullName(fullName);
        c.setEmail(email);
        c.setPhone(phone);
        c.setShippingAddress(address);
        c.setCity(city);
        c.setZipCode(zip);
        c.setRole(role);
        return customerRepo.save(c);
    }

    private Order createOrder(Long customerId, String date, String status, Double total,
                              String items, String tracking, String shippingAddress) {
        Order o = new Order();
        o.setCustomerId(customerId);
        o.setOrderDate(date);
        o.setStatus(status);
        o.setTotalAmount(total);
        o.setItems(items);
        o.setTrackingNumber(tracking);
        o.setShippingAddress(shippingAddress);
        return orderRepo.save(o);
    }

    private void createInvoice(Long customerId, Long orderId, String date,
                               Double subtotal, Double tax, Double total,
                               String paymentMethod, String billingAddress,
                               String status, String cardLast4) {
        Invoice i = new Invoice();
        i.setCustomerId(customerId);
        i.setOrderId(orderId);
        i.setInvoiceDate(date);
        i.setSubtotal(subtotal);
        i.setTax(tax);
        i.setTotal(total);
        i.setPaymentMethod(paymentMethod);
        i.setBillingAddress(billingAddress);
        i.setStatus(status);
        i.setCardLast4(cardLast4);
        invoiceRepo.save(i);
    }

    private void createWishlist(Long customerId, String product, Double price,
                                String date, String notes) {
        WishlistItem w = new WishlistItem();
        w.setCustomerId(customerId);
        w.setProductName(product);
        w.setPrice(price);
        w.setAddedDate(date);
        w.setNotes(notes);
        wishlistRepo.save(w);
    }
}
